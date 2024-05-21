#!/usr/bin/env pypy3

"""
Script to generate SYN flood traffic samples from a given list of sources

Want to emulate situation where each source sends SYNs at some particular rate.
"""

from scapy.all import *
from random import uniform
from multiprocessing import Process
from math import ceil
import sys

USAGE="<sources file> <output pcap file prefix> <target attack volume (bps)> <attack volume variance (+/- percent)> <duration (s)>"

DT = 0.001
TARGET_MAC = "00:01:02:03:04:05"
TARGET_IP = "10.10.1.1"
TARGET_PORT = 80

TIME_OFFSET = 1577917944.0

N_PROCS = 32

def getPkt(src):
    return Ether(dst=TARGET_MAC) \
         / IP(src=src, dst=TARGET_IP) \
         / TCP(flags="S", dport=TARGET_PORT)

def processChunk(state, duration, out_file):
    
    writer = PcapWriter(out_file)
    curTime = 0.0
    
    while curTime < duration:

        for i in range(len(state)):
            while state[i]["nextT"] <= curTime:
                pkt = getPkt(state[i]["src"])
                pkt.time = curTime + TIME_OFFSET
                writer.write(pkt)
                state[i]["nextT"] += state[i]["dt"]
        
        curTime += DT
        
    writer.close()

def chunks(arr, n):
    incr = ceil(float(len(arr)) / float(n))
    return [arr[start:start+incr] for start in range(0, len(arr), incr)]

def main():
    sources = open(sys.argv[1], "r").read().splitlines()
    out_prefix = sys.argv[2]
    target_bps = float(sys.argv[3])
    target_var = float(sys.argv[4])
    duration = float(sys.argv[5])

    pkt_size = len(getPkt("0.0.0.0"))
    target_agg_pps = target_bps / float(pkt_size * 8)

    num_sources = len(sources)
    target_pps = target_agg_pps / num_sources

    min_rate = target_pps - (target_pps * target_var)
    max_rate = target_pps + (target_pps * target_var)
    
    def initSrc(src):
        rate = uniform(min_rate, max_rate)
        dt = 1.0 / rate
        startT = uniform(0, dt)
        return dict(src=src, dt=dt, nextT=startT)
    state = list(map(initSrc, sources))

    stateChunks = chunks(state, N_PROCS)
    procs = [Process(target=processChunk, args=(stateChunks[i], duration, f"{out_prefix}_{i}.pcap")) for i in range(N_PROCS)]

    for p in procs:
        p.start()

    for p in procs:
        p.join()

    print("Done.")

if __name__ == "__main__":
    if len(sys.argv) != 6:
        print(USAGE)
        sys.exit()
    main()
