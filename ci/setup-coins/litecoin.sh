#!/bin/bash
set -euxo pipefail

config_dir="$(pwd)/config"
mkdir -p "$config_dir"

mkdir -p ~/coins/litecoin
cd ~/coins/litecoin

ltc_version="0.21.3" && curl https://download.litecoin.org/litecoin-"$ltc_version"/linux/litecoin-"$ltc_version"-x86_64-linux-gnu.tar.gz | tar -xzf -
mv litecoin-"$ltc_version" litecoin-node

python3 -m pip install virtualenv

git clone --depth 1 'https://github.com/spesmilo/electrumx'
pushd electrumx
virtualenv venv
./venv/bin/python3 -m pip install -e .
popd

git clone --depth 1 'https://github.com/pooler/electrum-ltc'
pushd electrum-ltc
python3 -m pip install --user -e .
popd

./litecoin-node/bin/litecoind -regtest -daemon -server=1 -txindex=1 -prune=0 -rpcport=19443 -rpcuser=ci -rpcpassword=password

mkdir -p /var/electrumx/db
chmod 777 -R /var/electrumx/db
ALLOW_ROOT=true COIN=Litecoin NET=regtest DB_DIRECTORY="/var/electrumx/db" DAEMON_URL="ci:password@127.0.0.1:19443" SERVICES="tcp://127.0.0.1:5000" PEER_DISCOVERY=self ./electrumx/venv/bin/python3 ./electrumx/electrumx_server &
sleep 1

./electrum-ltc/run_electrum --offline setconfig rpcport 3000
./electrum-ltc/run_electrum --offline setconfig rpcuser ci
./electrum-ltc/run_electrum --offline setconfig rpcpassword password
./electrum-ltc/run_electrum daemon -s 127.0.0.1:5000:t &
sleep 10
./electrum-ltc/run_electrum create
./electrum-ltc/run_electrum load_wallet

./litecoin-node/bin/litecoin-cli --rpcport=19443 -rpcuser=ci -rpcpassword=password createwallet ""
address="$(./litecoin-node/bin/litecoin-cli --rpcport=19443 -rpcuser=ci -rpcpassword=password getnewaddress)"
./litecoin-node/bin/litecoin-cli --rpcport=19443 -rpcuser=ci -rpcpassword=password generatetoaddress 110 "$address"

./litecoin-node/bin/litecoin-cli --rpcport=19443 -rpcuser=ci -rpcpassword=password sendtoaddress "$(./electrum-ltc/run_electrum getunusedaddress)" 100

destination="$(./electrum-ltc/run_electrum getunusedaddress)"
refund="$(./electrum-ltc/run_electrum getunusedaddress)"

cat > "$config_dir/litecoin.json" << EOF
{
  "url": "http://ci:password@127.0.0.1:3000",
  "ltc_url": "http://ci:password@127.0.0.1:18443",
  "destination": "$destination",
  "refund": "$refund"
}
EOF
