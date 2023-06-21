#!/bin/bash
#
# This script takes as input a file containing one URL per line. For each URL,
# it runs the request logger and writes its output to DOMAIN.json.

start=`date +%s`
script_dir=$(dirname "$0")
crawler="${script_dir}/run.js"
metamask_path="metamask-chrome-10.22.2"
destination="../results/whats_in_your_wallet/crawl"
logs="../results/whats_in_your_wallet/logs"
if [ $# != 1 ]
then
    >&2 echo "Usage: $0 FILE"
    exit 1
fi
file_name="$1"
counter=1
lines=$(wc -l < $file_name)
while read url; do
  echo "Crawling ${url} (${counter}/${lines//[[:blank:]]/})."
  domain=$(echo "$url" | awk -F/ '{print $3}')
  timeout 10m "$crawler" \
    --interactive \
    --debug verbose \
    --wallet "$metamask_path" \
    --ancestors \
    --destination "$destination" \
    -t 30 \
    --url "$url" > "${logs}/${domain}.log"
  counter=$[$counter +1]
done <"$file_name"
end=`date +%s`
runtime=$((end-start))
echo "Total execution time: ${runtime}s."
