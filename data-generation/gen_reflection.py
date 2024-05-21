#!/usr/bin/env pypy3

"""
Script to generate reflection attacks from a set of source addresses.

Accepts a pcap with a couple example reflection response packets (generate by filtering and using scripts/sample_n_packets.sh)
Each source selects a particular reflection response packet.
Packet level traffic is then generated similar to gen_flood.py
"""


from scapy.all import *
from random import uniform, sample
from multiprocessing import Process
from math import ceil
from copy import deepcopy
import sys

USAGE="<reflection packets file> <sources file> <output pcap file prefix> <target attack volume (bps)> <attack volume variance (+/- percent)> <duration (s)>"

DT = 0.001
TARGET_MAC = "00:01:02:03:04:05"
TARGET_IP = "10.10.1.1"

TIME_OFFSET = 1577917944.0

N_PROCS = 32
#N_PROCS = 1


def processChunk(state, duration, out_file):
    
    writer = PcapWriter(out_file)
    curTime = 0.0
    
    while curTime < duration:

        for i in range(len(state)):
            while state[i]["nextT"] <= curTime:
                pkt = state[i]["pkt"]
                pkt.time = curTime + TIME_OFFSET
                writer.write(pkt)
                state[i]["nextT"] += state[i]["dt"]
        
        curTime += DT
        
    writer.close()

def chunks(arr, n):
    incr = ceil(float(len(arr)) / float(n))
    return [arr[start:start+incr] for start in range(0, len(arr), incr)]

def main():
    attack_pkts = list(rdpcap(sys.argv[1]))
    sources = open(sys.argv[2], "r").read().splitlines()
    out_prefix = sys.argv[3]
    target_bps = float(sys.argv[4])
    target_var = float(sys.argv[5])
    duration = float(sys.argv[6])

    target_src_bps = target_bps / len(sources)
    
    def initSrc(src):
        pkt = deepcopy(sample(attack_pkts, 1)[0])
        pkt[Ether].dst = TARGET_MAC
        pkt[IP].dst = TARGET_IP
        pkt[IP].src = src

        target_pps = target_src_bps / (len(pkt) * 8)
        min_rate = target_pps - (target_pps * target_var)
        max_rate = target_pps + (target_pps * target_var)
        rate = uniform(min_rate, max_rate)
        dt = 1.0 / rate
        startT = uniform(0, dt)

        return dict(pkt=pkt, dt=dt, nextT=startT)

    state = list(map(initSrc, sources))

    stateChunks = chunks(state, N_PROCS)
    procs = [Process(target=processChunk, args=(stateChunks[i], duration, f"{out_prefix}_{i}.pcap")) for i in range(N_PROCS)]

    for p in procs:
        p.start()

    for p in procs:
        p.join()

    print("Done.")

if __name__ == "__main__":
    if len(sys.argv) != 7:
        print(USAGE)
        sys.exit()
    main()
