#!/usr/bin/env bash

NUM_SRCS=(
    500
    1000
    2000
    5000
    10000
    20000
    50000
)

NUM_SAMPLES=10

for i in ${NUM_SRCS[@]}
do
  for j in `seq ${NUM_SAMPLES}`
  do
    echo Running for $i sources round $j
    ../Haskell/uniform-sources ${i} > ../random_srcs/uniform_${i}_${j}
  done
done

echo Done.
