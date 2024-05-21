#!/usr/bin/env bash

# Require SDE_INSTALL in the environment (so we point to a particular compiler)
[ -z $SDE_INSTALL ] && {
    echo "SDE_INSTALL is not set in environment"
    exit
}

P4C=${SDE_INSTALL}/bin/bf-p4c

IN_FILE=zapdos_tna.p4
OUT_FILE=zapdos_tna.tofino

$P4C --target tofino \
     --arch tna \
     --std p4_16 \
     -o $OUT_FILE \
     -g -v \
     $IN_FILE

ln -s $(pwd)/${OUT_FILE} ${SDE_INSTALL}/
