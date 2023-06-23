#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import math
import numpy
import hashlib
import pymongo
import requests
import operator
import matplotlib
import tldextract
import jsbeautifier

import matplotlib.pyplot as plt

from bson.son import SON

MONGO_HOST = "localhost"
MONGO_PORT = 27017

def get_fqdn(url):
    _, dn, tld = tldextract.extract(url)
    return dn + "." + tld

def main():
    mongo_connection = pymongo.MongoClient("mongodb://"+MONGO_HOST+":"+str(MONGO_PORT), maxPoolSize=None)
    collection = mongo_connection["web3_privacy"]["fingerprinting_results"]

    print("----------------------------------------------------------")
    print("  Wallet API Calls")
    print("----------------------------------------------------------")
    print()

    print("Total number of JavaScript calls:", collection.count_documents({}))
    websites = collection.distinct("url")
    print("Websites calling wallet APIs:", len(websites))
    scripts = collection.distinct("script")
    print("Scripts calling wallet APIs:", len(scripts))
    print()

    print("\\toprule")
    print("\\textbf{Rank} & \\textbf{Website} & \\textbf{Script Domain} & \\textbf{Wallet API} \\\\")
    print("\\midrule")
    cursor = collection.find({}).sort("tranco_rank").limit(10)
    for document in cursor:
        wallet_apis = ""
        if len(document["detected_wallet_apis"]) == 4:
            print(document["tranco_rank"], " & ", "\\textbf{"+document["url_domain"]+"}", " & ", document["script_domain"], " & ", "All", " & ", "\\\\")
        else:
            for api in document["detected_wallet_apis"]:
                if wallet_apis == "":
                    print(document["tranco_rank"], " & ", "\\textbf{"+document["url_domain"]+"}", " & ", document["script_domain"], " & ", "\\texttt{"+api+"}", " & ", "\\\\")
                else:
                    print("& & & ", "\\texttt{"+api+"}", " & \\\\")
                wallet_apis += "\\texttt{"+api+"} "
    print("\\bottomrule")
    print()

    explicit_scripts_with_evidence = set()
    explicit_scripts_without_evidence = set()
    implicit_scripts_with_evidence = set()
    implicit_scripts_without_evidence = set()
    combinations = dict()
    cursor = collection.find({})
    for document in cursor:
        if len(document["detected_wallet_apis"]) == 4:
            if len(document["evidence"]) == 0:
                implicit_scripts_without_evidence.add(document["script"])
            else:
                implicit_scripts_with_evidence.add(document["script"])
        else:
            if not ", ".join(document["detected_wallet_apis"]) in combinations:
                combinations[", ".join(document["detected_wallet_apis"])] = set()
            combinations[", ".join(document["detected_wallet_apis"])].add(document["script"])
            if len(document["evidence"]) == 0:
                explicit_scripts_without_evidence.add(document["script"])
            else:
                explicit_scripts_with_evidence.add(document["script"])
    print("Scripts with explicit calls with evidence:", len(explicit_scripts_with_evidence), "("+str(len(explicit_scripts_with_evidence)/len(scripts)*100.0)+"%)")
    print("Scripts with explicit calls without evidence:", len(explicit_scripts_without_evidence), "("+str(len(explicit_scripts_without_evidence)/len(scripts)*100.0)+"%)")
    print("Scripts with implicit calls with evidence:", len(implicit_scripts_with_evidence), "("+str(len(implicit_scripts_with_evidence)/len(scripts)*100.0)+"%)")
    print("Scripts with implicit calls without evidence:", len(implicit_scripts_without_evidence), "("+str(len(implicit_scripts_without_evidence)/len(scripts)*100.0)+"%)")
    print()
    for combination in combinations:
        combinations[combination] = len(combinations[combination])
    combinations = sorted(combinations.items(), key=operator.itemgetter(1))
    combinations.reverse()
    print("\\toprule")
    print("\\textbf{Wallet APIs Combinations} & \\textbf{Scripts} \\\\")
    print("\\midrule")
    for combination in combinations:
        print(combination[0], "\t & \t", combination[1], "\\\\")
    print("\\bottomrule")
    print()

    print("----------------------------------------------------------")
    print("  Browser Fingerprinting Prevalence")
    print("----------------------------------------------------------")
    print()

    fingerprinting_scripts = set()
    fingerprinting_websites = set()
    fingerprinting_explicit = set()
    fingerprinting_implicit = set()
    fingerprinting_categories = list()
    cursor = collection.find({"browser_fingerprinting": True})
    for document in cursor:
        fingerprinting_scripts.add(document["script"])
        fingerprinting_websites.add(document["url"])
        fingerprinting_categories.append(len(document["fingerprinting_categories"]))
        if len(document["detected_wallet_apis"]) == 4:
            fingerprinting_implicit.add(document["script"])
        else:
            fingerprinting_explicit.add(document["script"])
    print("Scripts performing browser fingeprinting:", len(fingerprinting_scripts), "("+str(len(fingerprinting_scripts)/len(scripts)*100.0)+"%)")
    print("Websites performing browser fingeprinting:", len(fingerprinting_websites), "("+str(len(fingerprinting_websites)/len(websites)*100.0)+"%)")
    print("Max number of fingerprinting categories:", numpy.max(fingerprinting_categories))
    print("Average number of fingerprinting categories:", numpy.mean(fingerprinting_categories))
    print("Median number of fingerprinting categories:", numpy.median(fingerprinting_categories))
    print("Scripts with explicit calls:", len(fingerprinting_explicit), "("+str(len(fingerprinting_explicit)/len(fingerprinting_scripts)*100.0)+"%)")
    print("Scripts with implicit calls:", len(fingerprinting_implicit), "("+str(len(fingerprinting_implicit)/len(fingerprinting_scripts)*100.0)+"%)")
    print()

    print("----------------------------------------------------------")
    print("  Categories")
    print("----------------------------------------------------------")
    print()

    print("\\toprule")
    print("\\textbf{Category} & \\textbf{Websites} & \\textbf{Third-Party Calls} & \\textbf{Top Website (Rank)} & \\textbf{Top Third-Party (Websites)} \\\\")
    print("\\midrule")
    documents = list(collection.aggregate([
        {"$unwind": "$category"},
        {"$group": {"_id": "$category", "count": {"$sum": 1}}},
        {"$sort": SON([("count", -1), ("_id", -1)])}
    ]))
    for document in documents[1:11]:
        third_party_calls = collection.count_documents({"category": document["_id"], "third_party": True})
        top_third_party = list(collection.aggregate([
            {"$match": {"category": document["_id"], "third_party": True}},
            {"$unwind": "$script_domain"},
            {"$group": {"_id": "$script_domain", "count": {"$sum": 1}}},
            {"$sort": SON([("count", -1), ("_id", -1)])}
        ]))
        top_website_domain = list(collection.find({"category": document["_id"]}).sort("tranco_rank"))[0]["url_domain"]
        top_website_rank = list(collection.find({"category": document["_id"]}).sort("tranco_rank"))[0]["tranco_rank"]
        if len(top_third_party) == 0:
            top_third_party.append({"_id": "-", "count": 0})
        print(document["_id"].replace("&", "\&"), " & ", document["count"], " & ", str(third_party_calls)+" ("+"{:.0f}".format(third_party_calls/document["count"]*100.0)+"\%)", " & ", top_website_domain, "("+str(top_website_rank)+")", " & ", top_third_party[0]["_id"], "("+str(top_third_party[0]["count"])+")", "\\\\")
    print("...", " & ", "...", " & ", "...", " & ", "...", "\\\\")
    for document in documents[len(documents)-10:]:
        top_third_party = list(collection.aggregate([
            {"$match": {"category": document["_id"], "third_party": True}},
            {"$unwind": "$script_domain"},
            {"$group": {"_id": "$script_domain", "count": {"$sum": 1}}},
            {"$sort": SON([("count", -1), ("_id", -1)])}
        ]))
        top_website_domain = list(collection.find({"category": document["_id"]}).sort("tranco_rank"))[0]["url_domain"]
        top_website_rank = list(collection.find({"category": document["_id"]}).sort("tranco_rank"))[0]["tranco_rank"]
        if len(top_third_party) == 0:
            top_third_party.append({"_id": "-", "count": 0})
        third_party_calls = collection.count_documents({"category": document["_id"], "third_party": True})
        print(document["_id"].replace("&", "\&"), " & ", document["count"], " & ", str(third_party_calls)+" ("+"{:.2f}".format(third_party_calls/document["count"]*100.0)+"\%)", " & ", top_website_domain, "("+str(top_website_rank)+")", " & ", top_third_party[0]["_id"], "("+str(top_third_party[0]["count"])+")", "\\\\")
    print("\\bottomrule")
    print()

    print("----------------------------------------------------------")
    print("  Third-Parties")
    print("----------------------------------------------------------")
    print()

    third_party_calls = collection.count_documents({"third_party": True})
    print("Calls made by third-parties:", third_party_calls, "("+str(third_party_calls/collection.count_documents({})*100.0)+"%)")
    print()

    cursor = collection.find({"third_party": True})
    websites_with_third_parties = set()
    third_party_scripts = set()
    third_party_domains = set()
    for document in cursor:
        websites_with_third_parties.add(document["url"])
        third_party_scripts.add(document["script"])
        third_party_domains.add(document["script_domain"])
    print("Websites with third-party scripts:", len(websites_with_third_parties), "("+str(len(websites_with_third_parties)/len(websites)*100.0)+"%)")
    print("Third-party scripts found:", len(third_party_scripts))
    print("Third-party domains found:", len(third_party_domains))

    benign_third_parties = ["adaround.net", "unpkg.com", "cloudfront.net", "magic.link", "opyn.co", "jsdelivr.net", "cronosmm.finance", "coinstats.app", "spooky.fi", "cloudflare.com"]
    print("Benign third-party domains found:", len(benign_third_parties))


    for t in third_party_domains:
        print(t)
        for s in third_party_scripts:
            if t in s:
                print(s)
                break

    print()
    print("\\toprule")
    print("\\textbf{Third-Party Name} & \\textbf{Third-Party Domain} & \\textbf{Third-Party Script} & \\textbf{API Call Type} & \\textbf{Websites} & \\textbf{Min. Rank} \\\\")
    print("\\midrule")
    documents = list(collection.aggregate([
        {"$match": {"third_party": True}},
        {"$unwind": "$script_domain"},
        {"$group": {"_id": "$script_domain", "count": {"$sum": 1}}},
        {"$sort": SON([("count", -1), ("_id", -1)])}
    ]))
    with open("../datasets/tracker_radar_entity_map.json", "r") as f:
        entities = json.load(f)
    top = 10
    counter = 0
    for document in documents:
        type = "Explicit"
        api_calls = list(collection.find({"script_domain": document["_id"]}).distinct("detected_wallet_apis"))
        if len(api_calls) == 4:
            type = "Implicit"
            continue
        entity = "-"
        for e in entities:
            if document["_id"] in entities[e]["properties"]:
                entity = entities[e]["displayName"]
                break
        scripts = set(list(collection.find({"script_domain": document["_id"]}).distinct("script")))
        min_rank = list(collection.find({"script_domain": document["_id"]}).sort("tranco_rank"))[0]["tranco_rank"]
        fingerprinting = ""
        if list(collection.find({"script": list(scripts)[-1]}))[0]["browser_fingerprinting"]:
            fingerprinting = "\\textbf{(F)}"
        counter += 1
        print(entity, " & ", "\\textbf{"+document["_id"]+"}", " & ", list(scripts)[-1]+" "+fingerprinting, " & ", type, " & ", document["count"], " & ", min_rank, "\\\\")
        if counter == top:
            break
    print("\\bottomrule")
    print()
    print("\\toprule")
    print("\\textbf{Third-Party Name} & \\textbf{Third-Party Domain} & \\textbf{Third-Party Script} & \\textbf{API Call Type} & \\textbf{Websites} & \\textbf{Min. Rank} \\\\")
    print("\\midrule")
    top = 10
    counter = 0
    for document in documents:
        type = "Explicit"
        api_calls = list(collection.find({"script_domain": document["_id"]}).distinct("detected_wallet_apis"))
        if len(api_calls) == 4:
            type = "Implicit"
        else:
            continue
        entity = "-"
        for e in entities:
            if document["_id"] in entities[e]["properties"]:
                entity = entities[e]["displayName"]
                break
        scripts = set(list(collection.find({"script_domain": document["_id"]}).distinct("script")))
        min_rank = list(collection.find({"script_domain": document["_id"]}).sort("tranco_rank"))[0]["tranco_rank"]
        fingerprinting = ""
        if list(collection.find({"script": list(scripts)[-1]}))[0]["browser_fingerprinting"]:
            fingerprinting = "\\textbf{(F)}"
        counter += 1
        print(entity, " & ", "\\textbf{"+document["_id"]+"}", " & ", list(scripts)[-1]+" "+fingerprinting, " & ", type, " & ", document["count"], " & ", min_rank, "\\\\")
        if counter == top:
            break
    print("\\bottomrule")
    print()


    print("----------------------------------------------------------")
    print("  URL and Code Similarity")
    print("----------------------------------------------------------")
    print()

    third_party_scripts = list(collection.find({"third_party": True}).distinct("script"))
    print("Third-party scripts to analyze:", len(third_party_scripts))
    cloud_flare_challenges = list()
    non_cloud_flare_challenges = list()
    for script in third_party_scripts:
        if "/cdn-cgi/challenge-platform/h/" in script:
            cloud_flare_challenges.append(script)
        else:
            non_cloud_flare_challenges.append(script)
    print("CloudFlare challenge scripts:", len(cloud_flare_challenges), "("+str(len(cloud_flare_challenges)/len(third_party_scripts)*100.0)+"%)")
    print("Non CloudFlare challenge scripts:", len(non_cloud_flare_challenges), "("+str(len(non_cloud_flare_challenges)/len(third_party_scripts)*100.0)+"%)")

    if not os.path.exists("similarities.json"):
        similarities = dict()
        script_hashes = dict()
        for script in non_cloud_flare_challenges:
            response = None
            try:
                response = requests.get(script, headers={
                    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:106.0) Gecko/20100101 Firefox/106.0'
                })
            except:
                continue
            if response:
                code = jsbeautifier.beautify(response.text)
                hash = hashlib.sha256(code.encode('utf-8')).hexdigest()
                script_hashes[script] = hash
                if not hash in similarities:
                    similarities[hash] = set()
                similarities[hash].add(get_fqdn(script))
        output = dict()
        for hash in similarities:
            if len(similarities[hash]) > 1:
                output[hash] = dict()
                output[hash]["third_parties"] = list(similarities[hash])
                output[hash]["third_party_scripts"] = list()
                for script in script_hashes:
                    if script_hashes[script] == hash:
                        output[hash]["third_party_scripts"].append(script)
        with open("similarities.json", "w") as f:
            json.dump(output, f, indent=4)

    print()
    with open("similarities.json", "r") as f:
        input = json.load(f)
        print("Clusters of scripts that share the same code:")
        for hash in input:
            print()
            print(" ", hash, input[hash]["third_parties"])
            for script in input[hash]["third_party_scripts"]:
                print("   ->", script)
    print()

    print("----------------------------------------------------------")
    print("  Blocklists")
    print("----------------------------------------------------------")
    print()

    blocklists = list(collection.find({}).distinct("blocklists"))
    if None in blocklists:
        blocklists.remove(None)
    values = dict()
    total = len(list(collection.find({"third_party": True}).distinct("script_domain")))
    total = total - len(benign_third_parties)
    print("Third-Parties:", total)
    print()
    for blocklist in blocklists:
        blocked_third_parties = len(list(collection.find({"blocklists": blocklist, "third_party": True}).distinct("script_domain")))
        values[blocklist] = [blocked_third_parties, total-blocked_third_parties]
        print(blocklist, blocked_third_parties)
    cursor = collection.find({"third_party": True})
    blocked_script_domain = set()
    for document in cursor:
        if len(document["blocklists"]) > 0:
            blocked_script_domain.add(document["script_domain"])
    values["Combined"] = [len(blocked_script_domain), total-len(blocked_script_domain)]
    blocklists.append("Combined")
    print("Combined", len(blocked_script_domain))
    plt.rcdefaults()
    matplotlib.rc("font",**{"family":"serif","serif":["Times"]})
    matplotlib.rc("text", usetex=True)
    plt.rcParams["figure.figsize"] = [7.50, 3.50]
    plt.rcParams["figure.autolayout"] = True
    plt.rcParams["font.size"] = 16
    data = numpy.array(list(values.values()))
    data_cum = data.cumsum(axis=1)
    fig, ax = plt.subplots()
    ax.invert_yaxis()
    ax.xaxis.set_visible(False)
    ax.set_xlim(0, numpy.sum(data, axis=1).max())
    colors = ["red", "darkgrey"]
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["bottom"].set_visible(False)
    ax.spines["left"].set_visible(False)
    plt.tick_params(left = False)
    for i, (color) in enumerate(zip(colors)):
        widths = data[:, i]
        starts = data_cum[:, i] - widths
        rects = ax.barh(blocklists, widths, left=starts, height=0.5, color=color, edgecolor=color, alpha=0.40)
        for rect in rects:
            ax.annotate(
                f'{rect.get_width():,d}',
                xy=(0.5, 0.4),
                xycoords=rect,
                xytext=(0, 0), textcoords='offset points',
                ha='center', va='center')
    plt.legend(["Blocked", "Not Blocked"], loc="lower center", ncol=2, bbox_to_anchor=(0.39, -0.25))
    plt.tight_layout()
    plt.savefig("blocklists.pdf", dpi=1000, bbox_inches="tight")

if __name__ == "__main__":
    main()
