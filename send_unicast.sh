#!/bin/bash

./ida -nbr_config configs/config_$1.txt -all_config configs/config_allpeers.txt -broadcast -msg_file $2 -mode unicast
