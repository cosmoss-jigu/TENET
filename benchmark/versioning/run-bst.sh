#!/bin/bash

threads="1 4 8 16 24 32 40 48"

sh rem.sh
echo "####################################"
echo "Evaluation Tree 1M Keys "
for thread in ${threads}
do
    echo "run bench-timestone u20 num thread ${thread}"
    sudo ./benchmark_tree_mvrlu -i1000000 -r2000000 -d15000 -u20 -n${thread}
	sh rem.sh
done

echo "####################################"
echo "Evaluation Tree 1M Keys "
sh rem.sh
for thread in ${threads}
do
    echo "run bench-timestone u200 num thread ${thread}"
    sudo ./benchmark_tree_mvrlu -i1000000 -r2000000 -d15000 -u200 -n${thread}
	sh rem.sh
done

echo "####################################"
echo "Evaluation Tree 1M Keys "
sh rem.sh
for thread in ${threads}
do
    echo "run bench-timestone u800 num thread ${thread}"
    sudo ./benchmark_tree_mvrlu -i1000000 -r2000000 -d15000 -u800 -n${thread}
	sh rem.sh
done
