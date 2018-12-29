#!/bin/bash

unset -v i
i=0
while :
do
    case $((${i} < ${1})) in
    0)
        break
        ;;
    esac
   ./ida -nbr_config configs/config_$i.txt  -all_config configs/config_allpeers.txt -mode unicast > server_$i.out 2>&1 &
   i=$((${i} + 1))
done
