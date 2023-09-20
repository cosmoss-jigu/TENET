#!/bin/bash

#threads="1 4 8 14 28 56 84 112 140 168 196 224 280 336 392 448"
threads="1 4 8 16 24 32 40 48 56 64"
data="10000"

echo "####################################"
echo "Evaluation Tree 10K "
sh rem.sh
for thread in ${threads}
do
    echo "run bench-timestone u200 num thread ${thread}"
    ./benchmark_tree_mvrlu -i10000 -r20000 -d10000 -u200 -n${thread}
	sh rem.sh
done
