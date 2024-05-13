#!/bin/bash
set -euxo pipefail

config_dir="$(pwd)/config"
mkdir -p "$config_dir"

mkdir -p ~/coins/litecoin
cd ~/coins/litecoin

ltc_version="0.21.3" && curl https://download.litecoin.org/litecoin-"$ltc_version"/linux/litecoin-"$ltc_version"-x86_64-linux-gnu.tar.gz | tar -xzf -
mv litecoin-"$ltc_version" litecoin-node

git clone --depth 1 'https://github.com/spesmilo/electrumx'

git clone --depth 1 'https://github.com/pooler/electrum-ltc'
pushd electrum-ltc
python3 -m pip install --user -e .
popd

./litecoin-node/bin/litecoind -regtest -daemon -server=1 -txindex=1 -prune=0 -rpcport=19443 -rpcuser=ci -rpcpassword=password

echo 'COIN=Litecoin' > ~/electrumx.conf
echo 'SERVICES=tcp://127.0.0.1:5000' > ~/electrumx.conf
echo 'DAEMON_URL=ci:password@127.0.0.1' > ~/electrumx.conf
echo 'PEER_DISCOVERY=self' > ~/electrumx.conf

./electrs/target/debug/electrs --network regtest &
./electrum-ltc/run_electrum --regtest --offline setconfig rpcport 3000
./electrum-ltc/run_electrum --regtest --offline setconfig rpcuser ci
./electrum-ltc/run_electrum --regtest --offline setconfig rpcpassword password
./electrum-ltc/run_electrum --regtest daemon -d -s 127.0.0.1:5000:t --nosegwit
./electrum-ltc/run_electrum --regtest create
./electrum-ltc/run_electrum --regtest load_wallet

address="$(./electrum-ltc/run_electrum --regtest getunusedaddress)"
./litecoin-node/bin/litecoin-cli -regtest -rpcuser=ci -rpcpassword=password generatetoaddress 110 "$address"

destination="$(./electrum-ltc/run_electrum --regtest getunusedaddress)"
refund="$(./electrum-ltc/run_electrum --regtest getunusedaddress)"

cat > "$config_dir/litecoin.json" << EOF
{
  "url": "http://ci:password@127.0.0.1:3000",
  "ltc_url": "http://ci:password@127.0.0.1:18443",
  "destination": "$destination",
  "refund": "$refund"
}
EOF
