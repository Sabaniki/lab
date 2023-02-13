#!/bin/bash
file=$1

cat ../../P4/log/$1 | grep -B 3 dbg_rtt | grep tmp_rtt > tmp.txt
echo "EOF" >> tmp.txt
cat tmp.txt | ./log_to_time.py > ./output/$1.dec.txt
rm tmp.txt