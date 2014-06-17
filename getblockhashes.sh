#!/bin/bash

for i in {100000..262943}
do
    bitcoind -testnet getblockhash $i
done
