#!/bin/bash

COLLECTORS="requests,targets,apis,screenshots"

URLFILE=$1
OUTDIR=$2
LOGFILE=$3

mkdir -p $OUTDIR

nohup npm run crawl -- -i $URLFILE  -o $OUTDIR -f -v -d $COLLECTORS > $LOGFILE &
