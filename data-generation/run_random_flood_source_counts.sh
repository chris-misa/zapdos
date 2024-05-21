#!/usr/bin/env bash

# Run all source counts for a single data set (train, valid, test) and (flooding) attack vector

ATTACK_VECTOR=syn
ATTACK_SRCS_SUFFIX=1
DATA_SET=uniform

# ATTACK_VECTOR=icmp
# ATTACK_SRCS_SUFFIX=2
# DATA_SET=uniform

# ATTACK_VECTOR=udp
# ATTACK_SRCS_SUFFIX=3
# DATA_SET=uniform


NUM_SRCS=(
    500
    1000
    2000
    5000
    10000
    20000
    50000
)

for i in ${NUM_SRCS[@]}
do
    echo Running for $i sources...
    taskset 0xFFFF0000FFFF0000 ./gen_flood.py \
        $ATTACK_VECTOR \
        ../random_srcs/${DATA_SET}_${i}_${ATTACK_SRCS_SUFFIX} \
        ../raw_attacks/${DATA_SET}_${i}_${ATTACK_VECTOR}/temp \
        1000000000 \
        0.01 \
        120
done

echo Done.
