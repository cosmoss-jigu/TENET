#!/bin/bash

#threads="1 4 8 14 28 56 84 112 140 168 196 224 280 336 392 448"
threads="1 4 8 16 24 32 40 48"
data="10000"

sh rem.sh
echo "####################################"
echo "####################################"
echo "Evaluation Hash 1M Keys "
for thread in ${threads}
do
    echo "run bench-timestone u20 num thread ${thread}"
    sudo ./bench-timestone -a -b100000 -i1000000 -r2000000 -u20 -d15000 -n${thread}
	sh rem.sh
done

echo "####################################"
echo "####################################"
echo "Evaluation Hash 1M Keys "
for thread in ${threads}
do
    echo "run bench-timestone u200 num thread ${thread}"
   sudo ./bench-timestone -a -b100000 -i1000000 -r2000000 -u200 -d15000 -n${thread}
	sh rem.sh
done

echo "####################################"
echo "####################################"
echo "Evaluation Hash 1M Keys "
for thread in ${threads}
do
    echo "run bench-timestone u800 num thread ${thread}"
   sudo ./bench-timestone -a -b100000 -i1000000 -r2000000 -u800 -d15000 -n${thread}
	sh rem.sh
done

