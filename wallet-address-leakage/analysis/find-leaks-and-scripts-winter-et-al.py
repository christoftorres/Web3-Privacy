#!/usr/bin/env python3

import json
import os
import sys
import matplotlib.pyplot as plt
import publicsuffix2
import networkx as nx
import LeakDetector

from urllib.parse import urlparse

MAX_LEAK_DETECTION_LAYERS = 3

ETH_ADDR_WHATS_IN_YOUR_WALLET = "FDb672F061E5718eF0A56Db332e08616e9055548"
ETH_ADDR = "7e4ABd63A7C8314Cc28D388303472353D884f292"

DEBUG = False

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

def analyse_data(json_data, G, script_nodes, edges, addr_leaks, post_leaks, eth_address):
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
            # Get
            url_leaks_detected = detector.check_url(req["url"], encoding_layers=MAX_LEAK_DETECTION_LAYERS)
            if len(url_leaks_detected) > 0 or has_eth_addr(req["url"], eth_address.lower()):
                encoding = ""
                for url_leak in url_leaks_detected:
                    if url_leak[0].lower() != eth_address.lower():
                        encoding = url_leak[0]
                if DEBUG:
                    log(colors.OK+"Found leak (GET): "+req["url"]+" "+encoding+colors.END)
                addr_leaks[origin] = addr_leaks.get(origin, 0) + 1
                add_leak(domain, "GET", origin, leaks, req["url"], encoding)

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
                    addr_leaks[origin] = addr_leaks.get(origin, 0) + 1
                    post_leaks[origin] = post_leaks.get(origin, 0) + 1
                    add_leak(domain, type, origin, leaks, req["postData"], encoding)

            # Referer
            if "headers" in req and "referer" in req["headers"] and req["headers"]["referer"]:
                referrer_leaks_detected = detector.check_referrer_str(req["headers"]["referer"], encoding_layers=MAX_LEAK_DETECTION_LAYERS)
                if len(referrer_leaks_detected) > 0 or has_eth_addr(req["headers"]["referer"], eth_address.lower()):
                    encoding = ""
                    for referrer_leak in referrer_leaks_detected:
                        if referrer_leak[0].lower() != eth_address.lower():
                            encoding = referrer_leak[0]
                    add_leak(domain, "Referer", origin, leaks, req["headers"]["referer"], encoding)

            # Cookies
            if "responseHeaders" in req and req["responseHeaders"] and "set-cookie" in req["responseHeaders"] and req["responseHeaders"]["set-cookie"]:
                cookie_leaks_detected = detector.check_cookie_str(req["responseHeaders"]["set-cookie"], encoding_layers=MAX_LEAK_DETECTION_LAYERS)
                if len(cookie_leaks_detected) > 0 or has_eth_addr(req["responseHeaders"]["set-cookie"], eth_address.lower()):
                    encoding = ""
                    for cookie_leak in cookie_leaks_detected:
                        if cookie_leak[0].lower() != eth_address.lower():
                            encoding = cookie_leak[0]
                    add_leak(domain, "Cookies", origin, leaks, req["responseHeaders"]["set-cookie"], encoding)

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
                cookie_leaks_detected = detector.check_cookie_str(cookie["name"], encoding_layers=MAX_LEAK_DETECTION_LAYERS)
                if len(cookie_leaks_detected) > 0 or has_eth_addr(cookie["name"], eth_address.lower()):
                    encoding = ""
                    for cookie_leak in cookie_leaks_detected:
                        if cookie_leak[0].lower() != eth_address.lower():
                            encoding = cookie_leak[0]
                    add_leak(cookie["domain"], "Cookies", origin, leaks, cookie["name"], encoding)

    if DEBUG:
        log("Third-parties: "+str(list(script_domains)))
    log("Found "+colors.INFO+str(len(script_domains))+colors.END+" third-party script(s).")

    return leaks

def print_leaks(total, addr_leaks, post_leaks, whats_in_your_wallet_leaks):
    log("")
    ratio = len(addr_leaks) / total * 100
    log("Found "+colors.INFO+str(len(addr_leaks))+"/"+str(total)+" ("+str(int(ratio))+"%)"+colors.END+" websites leaking the Ethereum wallet address.")
    log("Number of 3rd party leaks per origin:")
    for origin, num_leaks in sorted(addr_leaks.items(),
                                    key=lambda x: x[1],
                                    reverse=True):
        if origin in whats_in_your_wallet_leaks:
            if origin in post_leaks:
                print("  "+colors.OK+str(num_leaks)+" \t "+origin+" [P]"+colors.END+" ")
            else:
                print("  "+colors.OK+str(num_leaks)+" \t "+origin+colors.END+" ")
        else:
            if origin in post_leaks:
                print("  {} \t {} [P] ".format(num_leaks, origin))
            else:
                print("  {} \t {} ".format(num_leaks, origin))
    log(" [P] This indicates that leaks happened via HTTP POST requests.")

def print_sourced_script_popularity():
    """Print the domains whose scripts are sourced by DeFi sites."""

    sorted_script_domains = sorted(script_nodes, key=lambda x:
                                   len([edge for edge in set(edges)]),
                                   reverse=True)
    log("# of embedded 3rd party domains: {}".format(len(sorted_script_domains)))
    for script_domain in sorted_script_domains:
        num = len([e for e in set(edges) if script_domain in e])
        print("{} & {} \\\\".format(script_domain, num))

    n = len(set([edge[0] for edge in edges]))
    log("# of DeFi sites that embed at least one script: {} ({:.0%})".format(
        n, n / len(defi_nodes)))

    # Find all edges that point to Google.
    n = len(set([edge[0] for edge in edges if "google" in edge[1]]))
    log("# of DeFi sites that embed Google scripts: {} ({:.0%})".format(
        n, n / len(defi_nodes)))

def create_connectivity_graph():
    """Create a connectivity graph of DeFi sites and their sourced scripts."""
    pos = nx.bipartite_layout(G, defi_nodes, align="horizontal")
    options = {"edgecolors": "tab:gray", "node_size": 800, "alpha": 0.9}
    nx.draw_networkx_nodes(G, pos, nodelist=list(defi_nodes), node_color="tab:blue", **options)
    nx.draw_networkx_nodes(G, pos, nodelist=script_nodes, node_color="tab:red", **options)
    nx.draw_networkx_edges(G, pos, edgelist=edges, width=2, alpha=0.3, edge_color="tab:gray")

    labels = {key: key for key in defi_nodes}
    text = nx.draw_networkx_labels(G, pos, labels, font_size=22)
    for _, t in text.items():
        t.set_rotation('vertical')

    labels = {key: key for key in script_nodes}
    text = nx.draw_networkx_labels(G, pos, labels, font_size=22)
    for _, t in text.items():
        t.set_rotation('vertical')

    plt.tight_layout()
    plt.show()

def parse_directory(directory, eth_address):
    """Iterate over the given directory and parse its JSON files."""
    log("")
    log("Parsing "+colors.INFO+directory+colors.END+" directory...")

    G = nx.DiGraph()
    defi_nodes = set()
    script_nodes = set()
    edges = []
    addr_leaks = {}

    total_sites = 0
    post_leaks = {}

    successful = 0
    connected = 0
    connect_labels = {}
    metamask_labels = {}

    leaks = dict()

    for file_name in os.listdir(directory):
        file_name = os.path.join(directory, file_name)
        if not os.path.isfile(file_name) or not file_name.endswith(".json"):
            if DEBUG:
                log("")
                log("Skipping {}; not a JSON file.".format(file_name))
            continue

        total_sites += 1

        log("")
        log("Parsing file: "+colors.INFO+file_name+colors.END)
        try:
            json_data = parse_file(file_name)
        except:
            print(colors.FAIL+"Error: Could not parse", file_name+colors.END)
            continue

        log("Extracted "+colors.INFO+str(len(json_data["requests"]))+colors.END+" requests from file: "+colors.INFO+file_name+colors.END)

        # Add DeFi site as new node to dependency graph.

        defi_domain = get_etld1(json_data["url"])
        G.add_node(defi_domain)
        defi_nodes.add(defi_domain)

        leaks.update(analyse_data(json_data, G, script_nodes, edges, addr_leaks, post_leaks, eth_address))

        """if json_data["success"]:
            successful += 1
        else:
            print(colors.FAIL+json_data["msg"]+colors.END)

        if json_data["connected"]:
            connected += 1
        else:
            log(colors.FAIL+"Could not connect MetaMask to: "+json_data["url"]+colors.END)

        if json_data["connect_label"]:
            if not json_data["connect_label"] in connect_labels:
                connect_labels[json_data["connect_label"]] = 0
            connect_labels[json_data["connect_label"]] += 1
            connect_labels = dict(sorted(connect_labels.items(), key=lambda item: item[1]))

        if json_data["metamask_label"]:
            if not json_data["metamask_label"] in metamask_labels:
                metamask_labels[json_data["metamask_label"]] = 0
            metamask_labels[json_data["metamask_label"]] += 1
            metamask_labels = dict(sorted(metamask_labels.items(), key=lambda item: item[1]))"""

    #log("")
    #log("Successful: "+str(successful)+"/"+str(total_sites)+"("+"{:.2f}".format(successful/total_sites*100.0)+"%)")
    #log("Connected: "+str(connected)+"/"+str(total_sites)+"("+"{:.2f}".format(connected/total_sites*100.0)+"%)")
    #import pprint
    #pprint.pprint(connect_labels)
    #pprint.pprint(metamask_labels)

    return leaks

def compare_leaks(other_leaks, our_leaks):
    sorted_domains = set()
    sorted_domains.update(list(other_leaks.keys()))
    sorted_domains.update(list(our_leaks.keys()))
    sorted_domains = list(sorted_domains)
    sorted_domains.sort()

    print("")
    print("\\toprule")
    print("\\textbf{DeFi Website} & \\textbf{GET}~\cite{winter2021web3} & \\textbf{GET} & \\textbf{POST} & \\textbf{WebSockets} & \\textbf{Cookies} \\\\")
    print("\\midrule")

    whats_in_your_wallet_third_parties_mapping = dict()
    whats_in_your_wallet_leaky_websites = 0
    whats_in_your_wallet_third_parties = set()
    whats_in_your_wallet_total_leaks = 0

    our_leaky_third_parties = dict()
    our_leaky_websites = 0

    our_leaky_gets_total = 0
    our_leaky_posts_total = 0
    our_leaky_websockets_total = 0
    our_leaky_cookies_total = 0

    our_leaky_gets_total_overlap = 0
    our_leaky_posts_total_overlap = 0
    our_leaky_websockets_total_overlap = 0
    our_leaky_cookies_total_overlap = 0

    total_post_websocket_cookies_leaks = 0

    for domain in sorted_domains:
        whats_in_your_wallet_third_parties_mapping[domain] = list()
        whats_in_your_wallet_leaks= 0

        if domain in other_leaks:
            for third_party in other_leaks[domain]["GET"]:
                whats_in_your_wallet_third_parties.add(third_party)
                whats_in_your_wallet_total_leaks += len(other_leaks[domain]["GET"][third_party])
                whats_in_your_wallet_leaks+= len(other_leaks[domain]["GET"][third_party])
                whats_in_your_wallet_third_parties_mapping[domain].append(third_party)
        else:
            whats_in_your_wallet_leaks= "0"

        our_leaks_number_get_third_parties, our_leaks_number_get_third_parties_overlap = 0, 0
        our_leaks_number_post_third_parties, our_leaks_number_post_third_parties_overlap = 0, 0
        our_leaks_number_websocket_third_parties, our_leaks_number_websocket_third_parties_overlap = 0, 0
        our_leaks_number_cookie_third_parties, our_leaks_number_cookie_third_parties_overlap = 0, 0

        if domain in our_leaks:
            our_leaky_websites += 1
            if "GET" in our_leaks[domain]:
                for third_party in our_leaks[domain]["GET"]:
                    if not third_party in our_leaky_third_parties:
                        our_leaky_third_parties[third_party] = dict()
                        our_leaky_third_parties[third_party]["GET"] = list()
                        our_leaky_third_parties[third_party]["POST"] = list()
                        our_leaky_third_parties[third_party]["WebSocket"] = list()
                        our_leaky_third_parties[third_party]["Cookies"] = list()
                    if not domain in our_leaky_third_parties[third_party]:
                        our_leaky_third_parties[third_party]["GET"].append(domain)
                    our_leaks_number_get_third_parties += len(our_leaks[domain]["GET"][third_party])
                    our_leaky_gets_total += len(our_leaks[domain]["GET"][third_party])
                    if third_party in whats_in_your_wallet_third_parties_mapping[domain]:
                        our_leaks_number_get_third_parties_overlap += len(our_leaks[domain]["GET"][third_party])
                        our_leaky_gets_total_overlap += len(our_leaks[domain]["GET"][third_party])
            if "POST" in our_leaks[domain]:
                for third_party in our_leaks[domain]["POST"]:
                    if not third_party in our_leaky_third_parties:
                        our_leaky_third_parties[third_party] = dict()
                        our_leaky_third_parties[third_party]["GET"] = list()
                        our_leaky_third_parties[third_party]["POST"] = list()
                        our_leaky_third_parties[third_party]["WebSocket"] = list()
                        our_leaky_third_parties[third_party]["Cookies"] = list()
                    if not domain in our_leaky_third_parties[third_party]:
                        our_leaky_third_parties[third_party]["POST"].append(domain)
                    our_leaks_number_post_third_parties += len(our_leaks[domain]["POST"][third_party])
                    our_leaky_posts_total += len(our_leaks[domain]["POST"][third_party])
                    total_post_websocket_cookies_leaks += len(our_leaks[domain]["POST"][third_party])
                    if third_party in whats_in_your_wallet_third_parties_mapping[domain]:
                        our_leaks_number_post_third_parties_overlap += len(our_leaks[domain]["POST"][third_party])
                        our_leaky_posts_total_overlap += len(our_leaks[domain]["POST"][third_party])
            if "WebSocket" in our_leaks[domain]:
                for third_party in our_leaks[domain]["WebSocket"]:
                    if not third_party in our_leaky_third_parties:
                        our_leaky_third_parties[third_party] = dict()
                        our_leaky_third_parties[third_party]["GET"] = list()
                        our_leaky_third_parties[third_party]["POST"] = list()
                        our_leaky_third_parties[third_party]["WebSocket"] = list()
                        our_leaky_third_parties[third_party]["Cookies"] = list()
                    if not domain in our_leaky_third_parties[third_party]:
                        our_leaky_third_parties[third_party]["WebSocket"].append(domain)
                    our_leaks_number_websocket_third_parties += len(our_leaks[domain]["WebSocket"][third_party])
                    our_leaky_websockets_total += len(our_leaks[domain]["WebSocket"][third_party])
                    total_post_websocket_cookies_leaks += len(our_leaks[domain]["WebSocket"][third_party])
                    if third_party in whats_in_your_wallet_third_parties_mapping[domain]:
                        our_leaks_number_websocket_third_parties_overlap += len(our_leaks[domain]["WebSocket"][third_party])
                        our_leaky_websockets_total_overlap += len(our_leaks[domain]["WebSocket"][third_party])
            if "Cookies" in our_leaks[domain]:
                for third_party in our_leaks[domain]["Cookies"]:
                    if not third_party in our_leaky_third_parties:
                        our_leaky_third_parties[third_party] = dict()
                        our_leaky_third_parties[third_party]["GET"] = list()
                        our_leaky_third_parties[third_party]["POST"] = list()
                        our_leaky_third_parties[third_party]["WebSocket"] = list()
                        our_leaky_third_parties[third_party]["Cookies"] = list()
                    if not domain in our_leaky_third_parties[third_party]:
                        our_leaky_third_parties[third_party]["Cookies"].append(domain)
                    for leak in our_leaks[domain]["Cookies"][third_party]:
                        print(third_party, leak)
                    our_leaks_number_cookie_third_parties += len(our_leaks[domain]["Cookies"][third_party])
                    our_leaky_cookies_total += len(our_leaks[domain]["Cookies"][third_party])
                    total_post_websocket_cookies_leaks += len(our_leaks[domain]["Cookies"][third_party])
                    if third_party in whats_in_your_wallet_third_parties_mapping[domain]:
                        our_leaks_number_cookie_third_parties_overlap += len(our_leaks[domain]["Cookies"][third_party])
                        our_leaky_cookies_total_overlap += len(our_leaks[domain]["Cookies"][third_party])

        our_leaks_number_get_third_parties_overlap = "("+str(our_leaks_number_get_third_parties_overlap)+")"
        our_leaks_number_post_third_parties_overlap = "("+str(our_leaks_number_post_third_parties_overlap)+")"
        our_leaks_number_websocket_third_parties_overlap = "("+str(our_leaks_number_websocket_third_parties_overlap)+")"
        our_leaks_number_cookie_third_parties_overlap = "("+str(our_leaks_number_cookie_third_parties_overlap)+")"

        print(str("\\textbf{"+domain+"}").ljust(26), "&", whats_in_your_wallet_leaks, " & ", our_leaks_number_get_third_parties, our_leaks_number_get_third_parties_overlap, " & ", our_leaks_number_post_third_parties, our_leaks_number_post_third_parties_overlap, " & ", our_leaks_number_websocket_third_parties, our_leaks_number_websocket_third_parties_overlap, " & ", our_leaks_number_cookie_third_parties, our_leaks_number_cookie_third_parties_overlap, "\\\\")

    print("\\midrule")
    print(str("\\textbf{Total}").ljust(26), "&", whats_in_your_wallet_total_leaks, " & ", our_leaky_gets_total, "("+str(our_leaky_gets_total_overlap)+")", " & ", our_leaky_posts_total, "("+str(our_leaky_posts_total_overlap)+")", " & ", our_leaky_websockets_total, "("+str(our_leaky_websockets_total_overlap)+")", " & ", our_leaky_cookies_total, "("+str(our_leaky_cookies_total_overlap)+")", "\\\\")
    print("\\bottomrule")
    print()
    print("Whats in your wallet leaky websites:", whats_in_your_wallet_leaky_websites)
    print("Our leaky websites:", our_leaky_websites)
    print()
    print("Number of identified third-parties by whats in your wallet:", len(whats_in_your_wallet_third_parties))
    print("Number of identified third-parties:", len(our_leaky_third_parties))
    print()
    print("Total leaks detected by whats in your wallet:", whats_in_your_wallet_total_leaks)
    print("Total leaks detected by us:", our_leaky_gets_total+our_leaky_posts_total+our_leaky_websockets_total+our_leaky_cookies_total)
    print("Total leaks detected via POST, WebSockets, and Cookies:", total_post_websocket_cookies_leaks)

    """sorted_third_parties = dict()
    for third_party in our_leaky_third_parties:
        total = 0
        total += len(our_leaky_third_parties[third_party]["GET"])
        total += len(our_leaky_third_parties[third_party]["POST"])
        total += len(our_leaky_third_parties[third_party]["WebSocket"])
        total += len(our_leaky_third_parties[third_party]["Cookies"])
        sorted_third_parties[third_party] = [total, len(our_leaky_third_parties[third_party]["GET"]), len(our_leaky_third_parties[third_party]["POST"]), len(our_leaky_third_parties[third_party]["WebSocket"]), len(our_leaky_third_parties[third_party]["Cookies"])]
    sorted_third_parties = dict(sorted(sorted_third_parties.items(), key=lambda x:x[0]))
    sorted_third_parties = dict(sorted(sorted_third_parties.items(), key=lambda x:x[1][0], reverse=True))

    top = 20
    print()
    print("\\toprule")
    print("\\textbf{Third-Party} & \\textbf{Websites} &	\\textbf{GET} & \\textbf{POST} & \\textbf{WebSockets} & \\textbf{Cookies} \\\\")
    print("\\midrule")
    for i in range(len(sorted_third_parties)):
        if i < top:
            third_party = list(sorted_third_parties.keys())[i]
            print(str("\\textbf{"+third_party+"}").ljust(26), " & ", sorted_third_parties[third_party][0], " & ", sorted_third_parties[third_party][1], " & ", sorted_third_parties[third_party][2], " & ", sorted_third_parties[third_party][3], " & ", sorted_third_parties[third_party][4], "\\\\")
    print("\\bottomrule")"""

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: {} <DIRECTORY_WITH_LATEST_CRAWLS> <DIRECTORY_WITH_WHATS_IN_YOUR_WALLET_CRAWLS>".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)
    our_leaks = parse_directory(sys.argv[1], ETH_ADDR)
    whats_in_your_wallet_leaks = parse_directory(sys.argv[2], ETH_ADDR_WHATS_IN_YOUR_WALLET)

    # create_connectivity_graph()
    #print_leaks(total_latest_sites, latest_leaks, post_leaks, whats_in_your_wallet_leaks)

    compare_leaks(whats_in_your_wallet_leaks, our_leaks)

    #print_sourced_script_popularity()
