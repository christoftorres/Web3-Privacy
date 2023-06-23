#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import csv
import json
import copy
import sqlite3
import pymongo
import requests
import tldextract
import jsbeautifier

from adblockparser import AdblockRules
from trackingprotection_tools import DisconnectParser

class colors:
    INFO = '\033[94m'
    OK = '\033[92m'
    FAIL = '\033[91m'
    END = '\033[0m'

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:106.0) Gecko/20100101 Firefox/106.0'
}

MONGO_HOST = "localhost"
MONGO_PORT = 27017

RESULTS_FOLDER = "../results/crawl"

TRANCO_FILE = "../datasets/tranco/tranco_6JXYX_november_2022.csv"

WEB3_APIS = ["window.ethereum", "window.cardano", "window.solana", "window.BinanceChain"]

BROWSER_FINGERPRINTING_THRESHOLD = 10
EXPLICIT_BROWSER_FINGERPRINTING_CATEGORIES = ["RTC", "WebGL", "Canvas", "Battery", "Plugins", "Device", "Audio", "SpeechSynthesis"]

ADBLOCK_OPTIONS = {"third-party": True}

def get_fingerprinting_category(api):
    category = ""
    if api in WEB3_APIS:
        category = "Wallet"
    elif api.startswith("RTCPeerConnection") or api.startswith("RTCPeerConnectionIceEvent"):
        category = "RTC"
    elif api.startswith("WebGLRenderingContext"):
        category = "WebGL"
    elif api.startswith("HTMLCanvasElement") or api.startswith("CanvasRenderingContext2D"):
        category = "Canvas"
    elif "Storage" in api or "indexedDB" in api:
        category = "Storage"
    elif "screen" in api or api.startswith("Screen"):
        category = "ScreenSize"
    elif "cookie" in api:
        category = "Cookies"
    elif api.startswith("Date") or "DateTimeFormat" in api:
        category = "DateTime"
    elif "getBattery" in api:
        category = "Battery"
    elif "Height" in api or "Width" in api or api.startswith("BarProp"):
        category = "WindowSize"
    elif "connection" in api or "onLine" in api:
        category = "Connection"
    elif "devicePixelRatio" in api:
        category = "ScreenResolution"
    elif "window.name" in api:
        category = "WindowLocation"
    elif "plugins" in api or "mimeType" in api or "canPlayType" in api:
        category = "Plugins"
    elif "vendor" in api or "product" in api or "platform" in api or "app" in api or "userAgent" in api:
        category = "Browser"
    elif "language" in api:
        category = "Language"
    elif api.startswith("DeviceOrientationEvent") or api.startswith("DeviceMotionEvent") or "maxTouchPoints" in api or "hardwareConcurrency" in api or "deviceMemory" in api or "memory" in api:
        category = "Device"
    elif api.startswith("AudioBuffer") or api.startswith("OfflineAudioContext"):
        category = "Audio"
    elif "requestMediaKeySystemAccess" in api or "mediaDevices" in api or "enumerateDevice" in api or "mediaCapabilities" in api:
        category = "Media"
    elif api.startswith("Navigator"):
        category = "Navigator"
    elif api.startswith("Performance"):
        category = "Performance"
    elif api.startswith("speechSynthesis"):
        category = "SpeechSynthesis"
    if category != "":
        return category
    return ""

def get_fqdn(url):
    _, dn, tld = tldextract.extract(url)
    return dn + "." + tld

def trace_back_initiator(script, initialUrl, requests, trace, traces):
    if not script in trace:
        trace.append(script)
        for request in requests:
            if request["url"] == script:
                if len(request["initiators"]) > 0:
                    for initiator in request["initiators"]:
                        if not initiator in trace:
                            trace_back_initiator(initiator, initialUrl, requests, copy.copy(trace), traces)
                else:
                    if not trace in traces:
                        traces.append(copy.copy(trace))
    return traces

def main():
    print("Loading EasyList rules...")
    easylist_rules = AdblockRules(set([l.strip() for l in open("../datasets/blocklists/easylist.txt") if len(l) != 0 and l[0] != '!']))
    print("Loading EasyPrivacy rules...")
    easyprivacy_rules = AdblockRules(set([l.strip() for l in open("../datasets/blocklists/easyprivacy.txt") if len(l) != 0 and l[0] != '!']))
    print("Loading Disconnect rules...")
    disconnect_rules = DisconnectParser(blocklist="../datasets/blocklists/disconnect.json")
    print("Loading Whotracks.me rules...")
    sql_query = """
      SELECT categories.name, tracker, domain FROM tracker_domains
      INNER JOIN trackers ON trackers.id = tracker_domains.tracker
      INNER JOIN categories ON categories.id = trackers.category_id;
    """
    con = sqlite3.connect(":memory:")
    sql_script = ""
    with open("../datasets/blocklists/whotracksme_trackerdb.sql", "r") as f:
        sql_script = f.read()
    con.executescript(sql_script)
    cur = con.cursor()
    whotracksme_rules = set()
    for (category, tracker, domain) in cur.execute(sql_query):
        whotracksme_rules.add(domain)
    con.close()
    print("Loading DuckDuckGo rules...")
    duckduckgo_rules = set()
    with open("../datasets/blocklists/duckduckgo_tds.json", "r") as f:
        duckduckgo_tds = json.load(f)
        for tracker in duckduckgo_tds["trackers"]:
            if duckduckgo_tds["trackers"][tracker]["default"] == "block":
                duckduckgo_rules.add(duckduckgo_tds["trackers"][tracker]["domain"])

    mongo_connection = pymongo.MongoClient("mongodb://"+MONGO_HOST+":"+str(MONGO_PORT), maxPoolSize=None)
    collection = mongo_connection["web3_privacy"]["fingerprinting_results"]

    findings = dict()
    for path, subdirs, files in os.walk(RESULTS_FOLDER):
        for name in files:
            if name.endswith(".json") and name != "metadata.json":
                with open(os.path.join(path, name), "r") as f:
                    result = json.load(f)
                    call_stats = result["data"]["apis"]["callStats"]
                    for script in call_stats:
                        if any([True for api in WEB3_APIS if api in call_stats[script]]):
                            trace = trace_back_initiator(script, result["initialUrl"], result["data"]["requests"], list(), list())
                            if not result["initialUrl"] in findings:
                                findings[result["initialUrl"]] = dict()
                            if not script in findings[result["initialUrl"]]:
                                findings[result["initialUrl"]][script] = dict()
                            findings[result["initialUrl"]][script] = (call_stats[script], trace)

    ranks = dict()
    with open(TRANCO_FILE, "r") as f:
        reader = csv.reader(f)
        for row in reader:
            ranks[row[1]] = row[0]

    tracker_radar_entity_map = dict()
    with open("../datasets/tracker_radar_entity_map.json", "r") as f:
        tracker_radar_entity_map = json.load(f)

    print()
    print("Found"+colors.INFO, len(findings), colors.END+"website(s) accessing web3 JavaScript object.")

    for url in findings:
        if len(findings[url]) > 1:
            print(url)
            for script in findings[url]:
                print(" ", script)
            print("")

    for url in findings:
        print()
        print(url)
        exists = mongo_connection["web3_privacy"]["fingerprinting_results"].find_one({"url": url})
        if exists:
            print("URL "+url+" already analyzed!")
            continue
        for script in findings[url]:
            initiator = ""
            party = "First-Party"
            traces = list()
            call_traces = list()
            for trace in findings[url][script][1]:
                spaces = ""
                trace_output = ""
                initiator = ""
                call_trace = list()
                for call in trace:
                    if initiator == "":
                        initiator = call
                    elif initiator != get_fqdn(call) and get_fqdn(call) != get_fqdn(url):
                        entity_mapping_found = False
                        for company in tracker_radar_entity_map:
                            for property in tracker_radar_entity_map[company]["properties"]:
                                if get_fqdn(call) == property:
                                    if get_fqdn(url) in tracker_radar_entity_map[company]["properties"]:
                                        entity_mapping_found = True
                        if not entity_mapping_found:
                            initiator = call
                    elif get_fqdn(call) == get_fqdn(url):
                        break
                for call in reversed(trace):
                    trace_output += spaces+" -> "+colors.INFO+get_fqdn(call)+colors.END+"\n"
                    spaces += " "
                    call_trace.append(call)
                if not trace_output in traces:
                    print(trace_output[:len(trace_output)-1])
                traces.append(trace_output)
                call_traces.append(call_trace)
            if initiator == "":
                initiator = url
            if get_fqdn(url).split(".")[0] != get_fqdn(initiator).split(".")[0]:
                entity_mapping_found = False
                for company in tracker_radar_entity_map:
                    for property in tracker_radar_entity_map[company]["properties"]:
                        if get_fqdn(initiator) == property:
                            if get_fqdn(url) in tracker_radar_entity_map[company]["properties"]:
                                entity_mapping_found = True
                if not entity_mapping_found:
                    party = "Third-Party"
            if party == "First-Party":
                print(" - ", colors.INFO+script+colors.END, colors.OK+"("+party+": "+get_fqdn(initiator)+")"+colors.END)
            else:
                print(" - ", colors.INFO+script+colors.END, colors.FAIL+"("+party+": "+get_fqdn(initiator)+")"+colors.END)
            categorization = requests.post("https://www.safedns.com/api/check-website", json={"domain": get_fqdn(url)}).json()
            category = ""
            try:
                category = [categorization["domain_cats"][cat] for cat in categorization["domain_cats"]][0]
            except:
                pass
            rank = ""
            beautified_js = ""
            evidence = list()
            if get_fqdn(url) in ranks:
                rank = int(ranks[get_fqdn(url)])
            print(os.path.join("../results/evidence", get_fqdn(url), script.split("/")[-1].split("?")[0])+".js")
            if not os.path.exists(os.path.join("../results/evidence", get_fqdn(url), script.split("/")[-1].split("?")[0])+".js"):
                try:
                    response = requests.get(script, headers=HEADERS)
                    if not os.path.exists("../results/evidence"):
                        os.mkdir("../results/evidence")
                    if not os.path.exists(os.path.join("../results/evidence", get_fqdn(url))):
                        os.mkdir(os.path.join("../results/evidence", get_fqdn(url)))
                    script_file_name = script.split("/")[-1].split("?")[0]
                    if script_file_name == "":
                        script_file_name = "index.js"
                    else:
                        script_file_name = script_file_name + ".js"
                    beautified_js = jsbeautifier.beautify(response.text)
                    if beautified_js:
                        open(os.path.join("../results/evidence", get_fqdn(url), script_file_name), "w").write(beautified_js)
                        for api in WEB3_APIS:
                            if api.replace("window.", "") in beautified_js:
                                evidence.append(api.replace("window.", ""))
                except:
                    pass
            else:
                with open(os.path.join("../results/evidence", get_fqdn(url), script.split("/")[-1].split("?")[0])+".js", "r") as f:
                    beautified_js = f.read()
                    for api in WEB3_APIS:
                        if api.replace("window.", "") in beautified_js:
                            evidence.append(api.replace("window.", ""))
            fingerprinting_categories = set()
            detected_wallet_apis = list()
            for api in findings[url][script][0]:
                fingerprinting_category = get_fingerprinting_category(api)
                if fingerprinting_category:
                    fingerprinting_categories.add(fingerprinting_category)
                    fingerprinting_category = "("+fingerprinting_category+")"
                api_name = api
                if api in WEB3_APIS:
                    api_name = colors.FAIL+api+colors.END
                    detected_wallet_apis.append(api)
                print("   - ", api_name, colors.INFO+str(findings[url][script][0][api])+colors.END, colors.OK+fingerprinting_category+colors.END)
            browser_fingerprinting = False
            if len(fingerprinting_categories) >= BROWSER_FINGERPRINTING_THRESHOLD and any([True for c in fingerprinting_categories if c in EXPLICIT_BROWSER_FINGERPRINTING_CATEGORIES]):
                browser_fingerprinting = True
            if browser_fingerprinting:
                print("Fingerprinting categories detected", colors.INFO+str(len(fingerprinting_categories))+colors.END, colors.FAIL+"(Browser fingerprinting detected)"+colors.END)
            else:
                print("Fingerprinting categories detected", colors.INFO+str(len(fingerprinting_categories))+colors.END)

            blocked = list()
            if easylist_rules.should_block(initiator, ADBLOCK_OPTIONS) or easylist_rules.should_block(script, ADBLOCK_OPTIONS):
                blocked.append("EasyList")
            if easyprivacy_rules.should_block(initiator, ADBLOCK_OPTIONS) or easyprivacy_rules.should_block(script, ADBLOCK_OPTIONS):
                blocked.append("EasyPrivacy")
            if disconnect_rules.should_block(initiator) or disconnect_rules.should_block(script):
                blocked.append("Disconnect")
            if get_fqdn(initiator) in whotracksme_rules or get_fqdn(script) in whotracksme_rules:
                blocked.append("Whotracks.me")
            if get_fqdn(initiator) in duckduckgo_rules or get_fqdn(script) in duckduckgo_rules:
                blocked.append("DuckDuckGo")

            finding = {
                "traces": call_traces,
                "tranco_rank": rank,
                "url": url,
                "url_domain": get_fqdn(url),
                "initiator": initiator,
                "initiator_domain": get_fqdn(initiator),
                "script": script,
                "script_domain": get_fqdn(script),
                "third_party": True if party == "Third-Party" else False,
                "browser_fingerprinting": browser_fingerprinting,
                "category": category,
                "blocklists": blocked,
                "detected_wallet_apis": detected_wallet_apis,
                "fingerprinting_categories": list(fingerprinting_categories),
                "evidence": evidence
            }

            collection.insert_one(finding)
            # Indexing...
            if 'url' not in collection.index_information():
                collection.create_index('tranco_rank')
                collection.create_index('url')
                collection.create_index('url_domain')
                collection.create_index('initiator')
                collection.create_index('initiator_domain')
                collection.create_index('script')
                collection.create_index('script_domain')
                collection.create_index('third_party')
                collection.create_index('browser_fingerprinting')
                collection.create_index('category')
                collection.create_index('blocklists')
                collection.create_index('detected_wallet_apis')
                collection.create_index('fingerprinting_categories')
                collection.create_index('evidence')

if __name__ == "__main__":
    main()
