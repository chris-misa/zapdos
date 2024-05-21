#!/usr/bin/env bash

# Run all source counts for a single data set (train, valid, test) and (reflection) attack vector

ATTACK_VECTOR=ntp
DATA_SET=train

#REFLECTION_PACKETS=../reflection_packets/booter1sample512.pcap
#REFLECTION_PACKETS=../reflection_packets/ssdp.pcap
REFLECTION_PACKETS=../reflection_packets/CICDDoS2019DayTwoNTP.pcap


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
    taskset 0xFFFF0000FFFF ./gen_reflection.py \
        $REFLECTION_PACKETS \
        ../mirai_srcs/attack_sets/${DATA_SET}_${i}_${ATTACK_VECTOR} \
        ../raw_attacks/${DATA_SET}_${i}_${ATTACK_VECTOR}/temp \
        1000000000 \
        0.01 \
        120
done

echo Done.
