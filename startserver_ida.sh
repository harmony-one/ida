#!/bin/bash

for i in {0..98}
do
   ./ida -nbr_config configs/config_$i.txt  -all_config configs/config_allpeers.txt &
done
