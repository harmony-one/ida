#!/bin/bash

mkdir -p "received"

if [ x$2 == "x" ]
then
./ida -nbr_config configs/config_$1.txt  -all_config configs/config_allpeers.txt
else
    echo $2
./ida -nbr_config configs/config_$1.txt -all_config configs/config_allpeers.txt -broadcast -msg_file $2
fi
