#!/bin/bash

threads="1 4 8 16 24 32 40 48"
data="10000"

sh rem.sh
echo "####################################"
echo "####################################"
echo "Evaluation List 100k Keys"
for thread in ${threads}
do
    echo "run bench-timestone u20 num thread ${thread}"
    sudo ./bench-timestone -a -b1 -i100000 -r200000 -u20 -d10000 -n${thread}
    sh rem.sh
done

sh rem.sh
echo "####################################"
echo "####################################"
echo "Evaluation List 100k Keys "
for thread in ${threads}
do
    echo "run bench-timestone u200 num thread ${thread}"
    sudo ./bench-timestone -a -b1 -i100000 -r200000 -u200 -d10000 -n${thread}
    sh rem.sh
done

sh rem.sh
echo "####################################"
echo "####################################"
echo "Evaluation List 100k Keys "
for thread in ${threads}
do
    echo "run bench-timestone u800 num thread ${thread}"
    sudo ./bench-timestone -a -b1 -i100000 -r200000 -u800 -d10000 -n${thread}
    sh rem.sh
done

