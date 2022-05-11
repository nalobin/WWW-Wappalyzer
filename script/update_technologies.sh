#!/usr/bin/env sh

# Download "technologies" and categiries JSON files
# from https://github.com/wappalyzer/wappalyzer into the repo.

SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

DEST_DIR=$SCRIPTPATH/../lib/WWW/wappalyzer_src

mkdir -p $DEST_DIR

TMP_DIR=`mktemp -d`

cd $TMP_DIR

git clone https://github.com/wappalyzer/wappalyzer.git

cd wappalyzer/src

cp -r categories.json groups.json technologies $DEST_DIR

rm -rf $TMP_DIR

