#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import csv
import json
import numpy
import operator
import matplotlib.pyplot as plt
import publicsuffix2
import networkx as nx
import LeakDetector

from urllib.parse import urlparse

MAX_LEAK_DETECTION_LAYERS = 3

ETH_ADDR = "7e4ABd63A7C8314Cc28D388303472353D884f292"

DEBUG = True

class colors:
    INFO = '\033[94m'
    OK = '\033[92m'
    FAIL = '\033[91m'
    END = '\033[0m'

def log(msg):
    """Log the given message to stderr."""
    print("[+] " + msg, file=sys.stderr)

def parse_file(file_name):
    """Parse the given JSON file and return its content."""
    with open(file_name, "r") as fd:
            json_data = json.load(fd)
    return json_data

def get_etld1(url):
    """Return the given URL's eTLD+1."""
    fqdn = urlparse(url).netloc
    fqdn = fqdn.split(":")[0]
    return publicsuffix2.get_sld(fqdn)

def has_eth_addr(url, eth_address):
    """Return True if the given URL contains our Ethereum address."""
    url = url.lower()
    return eth_address in url

def is_irrelevant(req):
    """Return True if the given request is irrelevant to our data analysis."""
    if req["url"].startswith("chrome-extension://"):
        return True
    return False

def is_same_request_context(request_context, origin):
    same = True
    for url in request_context:
        if get_etld1(url) != origin:
            same = False
    return same

def are_unrelated(domain, origin):
    """Return True if the two given domains are likely independent."""
    if domain != None and "." in domain:
        if origin.split('.')[-2] in domain.split('.')[-2]:
            return False
    return domain != origin

def add_leak(domain, type, origin, leaks, leak, encoding):
    if not origin in leaks:
        leaks[origin] = dict()
    if not type in leaks[origin]:
        leaks[origin][type] = dict()
    if not domain in leaks[origin][type]:
        leaks[origin][type][domain] = list()
    leaks[origin][type][domain].append((leak, encoding))

http_leaks = dict()
encoded_leaks = dict()

connect_labels = dict()
metamask_labels = dict()

def analyse_data(writer, json_data, G, script_nodes, edges, eth_address):
    origin = json_data["url"]
    reqs = json_data["requests"]
    script_domains = set()
    req_dst = {}
    origin = get_etld1(origin)

    log("Analyzing requests for origin: "+colors.INFO+origin+colors.END)

    search_terms = [eth_address, eth_address.lower(), eth_address.upper()]

    detector = LeakDetector.LeakDetector(
        search_terms,
        encoding_set=LeakDetector.LIKELY_ENCODINGS,
        hash_set=LeakDetector.LIKELY_HASHES,
        encoding_layers=MAX_LEAK_DETECTION_LAYERS,
        hash_layers=MAX_LEAK_DETECTION_LAYERS,
        debugging=False
    )

    leaks = {}

    for req in reqs:
        if is_irrelevant(req):
            continue
        if not is_same_request_context(req["requestContext"], origin):
            continue
        url = req["url"]
        domain = get_etld1(url)

        if domain != origin and domain != None:
            G.add_node(domain)
            script_domains.add(domain)
            script_nodes.add(domain)
            edges.append(tuple([origin, domain]))

        if are_unrelated(domain, origin):
            if req["url"].startswith("http") or req["url"].startswith("ws"):
                protocol = req["url"].split("://")[0]
                if protocol == "http" or protocol == "ws":
                    if not origin in http_leaks:
                        http_leaks[origin] = list()
                    http_leaks[origin].append(req["url"])

            # Get
            url_leaks_detected = detector.check_url(req["url"], encoding_layers=MAX_LEAK_DETECTION_LAYERS)
            if len(url_leaks_detected) > 0 or has_eth_addr(req["url"], eth_address.lower()):
                encoding = ""
                for url_leak in url_leaks_detected:
                    if url_leak[0].lower() != eth_address.lower():
                        encoding = url_leak[0]
                if DEBUG:
                    log(colors.OK+"Found leak (GET): "+req["url"]+" "+encoding+colors.END)
                add_leak(domain, "GET", origin, leaks, req["url"], encoding)
                writer.writerow([json_data["url"], req["url"], "GET", ""])

            # Post & WebSockets
            if "postData" in req:
                post_leaks_detected = detector.check_post_data(req["postData"], encoding_layers=MAX_LEAK_DETECTION_LAYERS)
                if len(post_leaks_detected) > 0 or has_eth_addr(req["postData"], eth_address.lower()):
                    type = req["type"] if req["type"] == "WebSocket" else "POST"
                    encoding = ""
                    for post_leak in post_leaks_detected:
                        if post_leak[0].lower() != eth_address.lower():
                            encoding = post_leak[0]
                    if DEBUG:
                        log(colors.OK+"Found leak ("+type+"): "+req["url"]+colors.END)
                    add_leak(domain, type, origin, leaks, req["postData"], encoding)
                    writer.writerow([json_data["url"], req["url"], type, req["postData"].replace("\n", "").replace("\r", "").replace("\x00", "").replace(" ", "")])

            # Referer
            if "headers" in req and "referer" in req["headers"] and req["headers"]["referer"]:
                referrer_leaks_detected = detector.check_referrer_str(req["headers"]["referer"], encoding_layers=MAX_LEAK_DETECTION_LAYERS)
                if len(referrer_leaks_detected) > 0 or has_eth_addr(req["headers"]["referer"], eth_address.lower()):
                    encoding = ""
                    for referrer_leak in referrer_leaks_detected:
                        if referrer_leak[0].lower() != eth_address.lower():
                            encoding = referrer_leak[0]
                    add_leak(domain, "Referer", origin, leaks, req["headers"]["referer"], encoding)
                    writer.writerow([json_data["url"], req["url"], "Referer", req["headers"]["referer"]])

            # Cookies
            if "responseHeaders" in req and req["responseHeaders"] and "set-cookie" in req["responseHeaders"] and req["responseHeaders"]["set-cookie"]:
                cookie_leaks_detected = detector.check_cookie_str(req["responseHeaders"]["set-cookie"], encoding_layers=MAX_LEAK_DETECTION_LAYERS)
                if len(cookie_leaks_detected) > 0 or has_eth_addr(req["responseHeaders"]["set-cookie"], eth_address.lower()):
                    encoding = ""
                    for cookie_leak in cookie_leaks_detected:
                        if cookie_leak[0].lower() != eth_address.lower():
                            encoding = cookie_leak[0]
                    add_leak(domain, "Cookies", origin, leaks, req["responseHeaders"]["set-cookie"], encoding)
                    writer.writerow([json_data["url"], req["url"], "Cookies", req["responseHeaders"]["set-cookie"]])

        req_dst[domain] = req_dst.get(domain, 0) + 1

        if "cookies" in json_data:
            for cookie in json_data["cookies"]:
                if are_unrelated(cookie["domain"], origin):
                    cookie_leaks_detected = detector.check_cookie_str(cookie["value"], encoding_layers=MAX_LEAK_DETECTION_LAYERS)
                    if len(cookie_leaks_detected) > 0 or has_eth_addr(cookie["value"], eth_address.lower()):
                        encoding = ""
                        for cookie_leak in cookie_leaks_detected:
                            if cookie_leak[0].lower() != eth_address.lower():
                                encoding = cookie_leak[0]
                        add_leak(cookie["domain"], "Cookies", origin, leaks, cookie["value"], encoding)
                        writer.writerow([json_data["url"], cookie["domain"], "Cookies", cookie["value"]])
                    cookie_leaks_detected = detector.check_cookie_str(cookie["name"], encoding_layers=MAX_LEAK_DETECTION_LAYERS)
                    if len(cookie_leaks_detected) > 0 or has_eth_addr(cookie["name"], eth_address.lower()):
                        encoding = ""
                        for cookie_leak in cookie_leaks_detected:
                            if cookie_leak[0].lower() != eth_address.lower():
                                encoding = cookie_leak[0]
                        add_leak(cookie["domain"], "Cookies", origin, leaks, cookie["name"], encoding)
                        writer.writerow([json_data["url"], cookie["domain"], "Cookies", cookie["name"]])

    if DEBUG:
        log("Third-parties: "+str(list(script_domains)))
    log("Found "+colors.INFO+str(len(script_domains))+colors.END+" third-party script(s).")

    return leaks, script_domains

def parse_directory(directory, eth_address, category):
    """Iterate over the given directory and parse its JSON files."""
    log("")
    log("Parsing "+colors.INFO+directory+colors.END+" directory...")

    G = nx.DiGraph()
    defi_nodes = set()
    script_nodes = set()
    edges = []

    total_sites = []
    total_third_parties = []

    connected = []

    leaks = dict()

    csvfile = open("dapps_"+category+"_leaks.csv", "w", encoding="utf-8")
    writer = csv.writer(csvfile, delimiter=';', quotechar='|', quoting=csv.QUOTE_MINIMAL)

    for file_name in os.listdir(directory):
        file_name = os.path.join(directory, file_name)
        if not os.path.isfile(file_name) or not file_name.endswith(".json"):
            if DEBUG:
                log("")
                log("Skipping {}; not a JSON file.".format(file_name))
            continue

        log("")
        log("Parsing file: "+colors.INFO+file_name+colors.END)
        try:
            json_data = parse_file(file_name)
        except:
            print(colors.FAIL+"Error: Could not parse", file_name+colors.END)
            continue

        if not "url" in json_data:
            continue

        defi_domain = get_etld1(json_data["url"])
        total_sites.append(defi_domain)


        log("Extracted "+colors.INFO+str(len(json_data["requests"]))+colors.END+" requests from file: "+colors.INFO+file_name+colors.END)

        # Add DeFi site as new node to dependency graph.
        G.add_node(defi_domain)
        defi_nodes.add(defi_domain)

        detected_leaks, detected_third_parties = analyse_data(writer, json_data, G, script_nodes, edges, eth_address)
        total_third_parties.append(list(detected_third_parties))
        leaks.update(detected_leaks)

        if json_data["connected"]:
            connected.append(defi_domain)

        if "connect_label" in json_data and json_data["connect_label"]:
            if not json_data["connect_label"] in connect_labels:
                connect_labels[json_data["connect_label"]] = 0
            connect_labels[json_data["connect_label"]] += 1
            connect_labels.update(dict(sorted(connect_labels.items(), key=lambda item: item[1])))

        if "metamask_label" in json_data and json_data["metamask_label"]:
            if not json_data["metamask_label"] in metamask_labels:
                metamask_labels[json_data["metamask_label"]] = 0
            metamask_labels[json_data["metamask_label"]] += 1
            metamask_labels.update(dict(sorted(metamask_labels.items(), key=lambda item: item[1])))

    csvfile.close()

    return total_sites, leaks, connected, total_third_parties

def add_leaks_to_results(results, total, leaks, connected, detected_third_parties, third_party_leaks, category):
    get_leaks = 0
    post_leaks = 0
    websocket_leaks = 0
    cookie_leaks = 0
    third_parties = set()
    for dapp in leaks:
        for type in leaks[dapp]:
            if type == "GET":
                for third_party in leaks[dapp][type]:
                    if not third_party in third_party_leaks:
                        third_party_leaks[third_party] = dict()
                        third_party_leaks[third_party]["GET"] = list()
                        third_party_leaks[third_party]["POST"] = list()
                        third_party_leaks[third_party]["WebSocket"] = list()
                        third_party_leaks[third_party]["Cookies"] = list()
                        third_party_leaks[third_party]["DApps"] = set()
                    third_party_leaks[third_party][type] += leaks[dapp][type][third_party]
                    third_party_leaks[third_party]["DApps"].add(dapp)
                    third_parties.add(third_party)
                    get_leaks += len(leaks[dapp][type][third_party])
                    for leak in leaks[dapp][type][third_party]:
                        if leak[1] != "" and leak[1] != "urlencode":
                            if not dapp in encoded_leaks:
                                 encoded_leaks[dapp] = list()
                            encoded_leaks[dapp].append((type, leak))
            if type == "POST":
                for third_party in leaks[dapp][type]:
                    if not third_party in third_party_leaks:
                        third_party_leaks[third_party] = dict()
                        third_party_leaks[third_party]["GET"] = list()
                        third_party_leaks[third_party]["POST"] = list()
                        third_party_leaks[third_party]["WebSocket"] = list()
                        third_party_leaks[third_party]["Cookies"] = list()
                        third_party_leaks[third_party]["DApps"] = set()
                    third_party_leaks[third_party][type] += leaks[dapp][type][third_party]
                    third_party_leaks[third_party]["DApps"].add(dapp)
                    third_parties.add(third_party)
                    post_leaks += len(leaks[dapp][type][third_party])
                    for leak in leaks[dapp][type][third_party]:
                        if leak[1] != "" and leak[1] != "urlencode":
                            if not dapp in encoded_leaks:
                                 encoded_leaks[dapp] = list()
                            encoded_leaks[dapp].append((type, leak))
            if type == "WebSocket":
                for third_party in leaks[dapp][type]:
                    if not third_party in third_party_leaks:
                        third_party_leaks[third_party] = dict()
                        third_party_leaks[third_party]["GET"] = list()
                        third_party_leaks[third_party]["POST"] = list()
                        third_party_leaks[third_party]["WebSocket"] = list()
                        third_party_leaks[third_party]["Cookies"] = list()
                        third_party_leaks[third_party]["DApps"] = set()
                    third_party_leaks[third_party][type] += leaks[dapp][type][third_party]
                    third_party_leaks[third_party]["DApps"].add(dapp)
                    third_parties.add(third_party)
                    websocket_leaks += len(leaks[dapp][type][third_party])
                    for leak in leaks[dapp][type][third_party]:
                        if leak[1] != "" and leak[1] != "urlencode":
                            if not dapp in encoded_leaks:
                                 encoded_leaks[dapp] = list()
                            encoded_leaks[dapp].append((type, leak))
            if type == "Cookies":
                for third_party in leaks[dapp][type]:
                    if not third_party in third_party_leaks:
                        third_party_leaks[third_party] = dict()
                        third_party_leaks[third_party]["GET"] = list()
                        third_party_leaks[third_party]["POST"] = list()
                        third_party_leaks[third_party]["WebSocket"] = list()
                        third_party_leaks[third_party]["Cookies"] = list()
                        third_party_leaks[third_party]["DApps"] = set()
                    third_party_leaks[third_party][type] += leaks[dapp][type][third_party]
                    third_party_leaks[third_party]["DApps"].add(dapp)
                    third_parties.add(third_party)
                    cookie_leaks += len(leaks[dapp][type][third_party])
                    for leak in leaks[dapp][type][third_party]:
                        if leak[1] != "" and leak[1] != "urlencode":
                            if not dapp in encoded_leaks:
                                 encoded_leaks[dapp] = list()
                            encoded_leaks[dapp].append((type, leak))
    results[category] = dict()
    results[category]["total_dapps"] = total
    results[category]["connected_dapps"] = connected
    results[category]["leaky_dapps"] = list(leaks.keys())
    results[category]["third_parties"] = list(third_parties)
    results[category]["get_leaks"] = get_leaks
    results[category]["post_leaks"] = post_leaks
    results[category]["websocket_leaks"] = websocket_leaks
    results[category]["cookie_leaks"] = cookie_leaks
    results[category]["detected_third_parties"] = detected_third_parties

if __name__ == "__main__":
    results = dict()
    third_party_leaks = dict()

    if not os.path.exists("dapps_results.json"):
        total, leaks, connected, third_parties = parse_directory("../results/dapps/crawl/dapps_collectibles/", ETH_ADDR, "collectibles")
        add_leaks_to_results(results, total, leaks, connected, third_parties, third_party_leaks, "Collectibles")

        total, leaks, connected, third_parties = parse_directory("../results/dapps/crawl/dapps_defi/", ETH_ADDR, "defi")
        add_leaks_to_results(results, total, leaks, connected, third_parties, third_party_leaks, "DeFi")

        total, leaks, connected, third_parties = parse_directory("../results/dapps/crawl/dapps_games/", ETH_ADDR, "games")
        add_leaks_to_results(results, total, leaks, connected, third_parties, third_party_leaks, "Games")

        total, leaks, connected, third_parties = parse_directory("../results/dapps/crawl/dapps_other/", ETH_ADDR, "other")
        add_leaks_to_results(results, total, leaks, connected, third_parties, third_party_leaks, "Other")

        total, leaks, connected, third_parties = parse_directory("../results/dapps/crawl/dapps_marketplaces/", ETH_ADDR, "marketplaces")
        add_leaks_to_results(results, total, leaks, connected, third_parties, third_party_leaks, "Marketplaces")

        total, leaks, connected, third_parties = parse_directory("../results/dapps/crawl/dapps_high_risk/", ETH_ADDR, "high_risk")
        add_leaks_to_results(results, total, leaks, connected, third_parties, third_party_leaks, "High Risk")

        total, leaks, connected, third_parties = parse_directory("../results/dapps/crawl/dapps_exchanges/", ETH_ADDR, "exchanges")
        add_leaks_to_results(results, total, leaks, connected, third_parties, third_party_leaks, "Exchanges")

        total, leaks, connected, third_parties = parse_directory("../results/dapps/crawl/dapps_gambling/", ETH_ADDR, "gambling")
        add_leaks_to_results(results, total, leaks, connected, third_parties, third_party_leaks, "Gambling")

        total, leaks, connected, third_parties = parse_directory("../results/dapps/crawl/dapps_social/", ETH_ADDR, "social")
        add_leaks_to_results(results, total, leaks, connected, third_parties, third_party_leaks, "Social")

        results["http_leaks"] = http_leaks
        results["encoded_leaks"] = encoded_leaks

        with open("dapps_results.json", "w") as f:
            json.dump(results, f, indent=4)

    print("connect_labels", connect_labels)
    print("metamask_labels", metamask_labels)

    with open("dapps_results.json", "r") as f:
        results = json.load(f)

    print()
    total_dapps = 0
    total_connected = 0
    total_connected_unique = set()
    for category in results:
        if category != "http_leaks" and category != "encoded_leaks":
            print("Successfully connected", category, "DApps:", len(results[category]["connected_dapps"]), "("+str(len(results[category]["connected_dapps"])/len(results[category]["total_dapps"])*100.0)+"%)")
            total_connected += len(results[category]["connected_dapps"])
            for connteced_dapp in results[category]["connected_dapps"]:
                total_connected_unique.add(connteced_dapp)
            total_dapps += len(results[category]["total_dapps"])
    print("Total successfully connected DApps:", total_connected, "("+str(total_connected/total_dapps*100.0)+"%)")
    print("Total successfully connected unique DApps:", len(total_connected_unique))
    print()
    print("\\toprule")
    print("\\textbf{Category} & \\textbf{DApps} & \\textbf{Third-Parties} & \\textbf{GET} & \\textbf{POST} & \\textbf{WebSockets} & \\textbf{Cookies} \\\\")
    print("\\midrule")
    total_dapps = set()
    total_third_parties = set()
    total_get_leaks = 0
    total_post_leaks = 0
    total_websocket_leaks = 0
    total_cookie_leaks = 0
    total_detected_third_parties = set()
    for category in results:
        if category != "http_leaks" and category != "encoded_leaks":
            total_dapps.update(set(results[category]["leaky_dapps"]))
            total_third_parties.update(set(results[category]["third_parties"]))
            total_get_leaks += results[category]["get_leaks"]
            total_post_leaks += results[category]["post_leaks"]
            total_websocket_leaks += results[category]["websocket_leaks"]
            total_cookie_leaks += results[category]["cookie_leaks"]
            detected_third_parties = set()
            for third_parties in results[category]["detected_third_parties"]:
                detected_third_parties.update(set(third_parties))
                total_detected_third_parties.update(set(third_parties))
            print(category, " & ", len(results[category]["leaky_dapps"]), "("+str(int(len(results[category]["leaky_dapps"])/len(results[category]["connected_dapps"])*100.0))+"\\%)", " & ", len(results[category]["third_parties"]), "("+str(int(len(results[category]["third_parties"])/len(detected_third_parties)*100.0))+"\\%)", " & ", results[category]["get_leaks"], " & ", results[category]["post_leaks"], " & ", results[category]["websocket_leaks"], " & ", results[category]["cookie_leaks"], "\\\\")
    print("\\midrule")
    print("\\textbf{Total Unique}", " & ", len(total_dapps), "("+str(int(len(total_dapps)/len(total_connected_unique)*100.0))+"\\%)", " & ", len(total_third_parties), "("+str(int(len(total_third_parties)/len(total_detected_third_parties)*100.0))+"\\%)", " & ", total_get_leaks, " & ", total_post_leaks, " & ", total_websocket_leaks, " & ", total_cookie_leaks, "\\\\")
    print("\\bottomrule")
    print()
    dapps_with_at_least_one_third_party = 0
    third_parties_per_dapp = list()
    for category in results:
        if category != "http_leaks" and category != "encoded_leaks":
            for third_parties in results[category]["detected_third_parties"]:
                if len(third_parties) > 0:
                    dapps_with_at_least_one_third_party += 1
                    third_parties_per_dapp.append(len(third_parties))
    print("DApps with at least one third-party:", dapps_with_at_least_one_third_party)
    print("Average number of third-parties per DApp:", numpy.mean(third_parties_per_dapp))
    print("Maximum number of third-parties per DApp:", numpy.max(third_parties_per_dapp))
    print()
    total_http_leaks = 0
    for website in results["http_leaks"]:
        total_http_leaks += len(results["http_leaks"][website])
    print("Insecure HTTP leaks found:", total_http_leaks)
    print("DApps with insecure HTTP leaks:", len(results["http_leaks"]))
    print()

    sorted_third_parties = dict()
    for third_party in third_party_leaks:
        sorted_third_parties[third_party] = [len(third_party_leaks[third_party]["DApps"]), len(third_party_leaks[third_party]["GET"]), len(third_party_leaks[third_party]["POST"]), len(third_party_leaks[third_party]["WebSocket"]), len(third_party_leaks[third_party]["Cookies"])]
    sorted_third_parties = dict(sorted(sorted_third_parties.items(), key=lambda x:x[0]))
    sorted_third_parties = dict(sorted(sorted_third_parties.items(), key=lambda x:x[1][0], reverse=True))
    top = 20
    print("\\toprule")
    print("\\textbf{Third-Party Name} & \\textbf{Third-Party Domain} & \\textbf{Category} & \\textbf{Collects IP Address} & \\textbf{DApps} & \\textbf{GET} & \\textbf{POST} & \\textbf{WebSockets} & \\textbf{Cookies} \\\\")
    print("\\midrule")
    for i in range(len(sorted_third_parties)):
        if i < top:
            third_party = list(sorted_third_parties.keys())[i]
            print(" & ", str("\\textbf{"+third_party+"}").ljust(26), " & ", " & ", " & ",sorted_third_parties[third_party][0], " & ", sorted_third_parties[third_party][1], " & ", sorted_third_parties[third_party][2], " & ", sorted_third_parties[third_party][3], " & ", sorted_third_parties[third_party][4], "\\\\")
    print("\\bottomrule")
    print()
