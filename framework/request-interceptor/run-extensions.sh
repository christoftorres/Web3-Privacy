#!/bin/bash
#
# This script takes as input a file containing a list of wallet extensions. For each wallet extension,
# it creates a seperate user profile, installs the extension, interacts with the extension, and stores its output to EXTENSION_ID.json.

start=`date +%s`
script_dir=$(dirname "$0")
crawler="${script_dir}/run.js"
destination="../results/extensions/crawl_new"
profiles="../results/extensions/profiles_new"
logs="../results/extensions/logs_new"
if [ $# != 1 ]
then
    >&2 echo "Usage: $0 FILE"
    exit 1
fi
file_name="$1"
counter=1
lines=$(wc -l < $file_name)
while read wallet_path; do
  echo "Setting up ${wallet_path} (${counter}/${lines//[[:blank:]]/})."
  id=$(echo ${wallet_path##*/})
  "$crawler" \
    --interactive \
    --debug verbose \
    --wallet "$wallet_path" \
    --ancestors \
    --destination "$destination" \
    -l 10 > "${logs}/${id}.log"
  counter=$[$counter +1]
done <"$file_name"
end=`date +%s`
runtime=$((end-start))
echo "Total execution time: ${runtime}s."
