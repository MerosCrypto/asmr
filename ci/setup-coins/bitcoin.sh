#!/bin/bash
set -euxo pipefail

config_dir="$(pwd)/config"
mkdir -p "$config_dir"

mkdir -p ~/coins/bitcoin
cd ~/coins/bitcoin

btc_version="0.20.1"
curl https://bitcoincore.org/bin/bitcoin-core-"$btc_version"/bitcoin-"$btc_version"-x86_64-linux-gnu.tar.gz | tar -xzf -
mv bitcoin-"$btc_version" bitcoin-node

if [ ! -e electrs/target/debug/electrs ]; then
    git clone --depth 1 --branch v0.8.5 'https://github.com/romanz/electrs' electrs
    pushd electrs
    cargo build
    popd
fi

git clone --depth 1 --branch 4.0.2 'https://github.com/spesmilo/electrum'
pushd electrum
python3 -m pip install --user -e .
popd

./bitcoin-node/bin/bitcoind -regtest -daemon -server=1 -txindex=1 -prune=0 -rpcport=18443 -rpcuser=ci -rpcpassword=password
echo 'cookie = "ci:password"' > electrs.toml
echo 'txid_limit = 0' >> electrs.toml
./electrs/target/debug/electrs --network regtest &
./electrum/run_electrum --regtest --offline setconfig rpcport 3000
./electrum/run_electrum --regtest --offline setconfig rpcuser ci
./electrum/run_electrum --regtest --offline setconfig rpcpassword password
./electrum/run_electrum --regtest daemon -d -s 127.0.0.1:60401:t
./electrum/run_electrum --regtest create
./electrum/run_electrum --regtest load_wallet

address="$(./electrum/run_electrum --regtest getunusedaddress)"
./bitcoin-node/bin/bitcoin-cli -regtest -rpcuser=ci -rpcpassword=password generatetoaddress 105 "$address"

destination="$(./electrum/run_electrum --regtest getunusedaddress)"
refund="$(./electrum/run_electrum --regtest getunusedaddress)"

cat > "$config_dir/bitcoin.json" << EOF
{
  "url": "http://ci:password@127.0.0.1:3000",
  "btc_url": "http://ci:password@127.0.0.1:18443",
  "destination": "$destination",
  "refund": "$refund"
}
EOF
