#!/usr/bin/env bash

# Merge results of parallel runs of gen_flood.py (e.g., when called through run_flood_source_counts.sh)

ATTACK_VECTOR=syn
DATA_SET=uniform


NUM_SRCS=(
    500
    1000
    2000
    5000
    10000
    20000
    50000
)

cd ../raw_attacks

for i in ${NUM_SRCS[@]}
do
    echo Running for $i sources...
    cd ${DATA_SET}_${i}_${ATTACK_VECTOR}
    mergecap -F pcap -w trace.pcap temp_*.pcap
    cd ..
done

echo Done.
