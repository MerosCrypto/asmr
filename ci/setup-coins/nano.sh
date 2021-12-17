#!/bin/bash
set -euxo pipefail

config_dir="$(pwd)/config"
mkdir -p "$config_dir"

mkdir -p ~/coins/nano
cd ~/coins/nano

if [ ! -f nano_node ]; then
  git clone --depth 1 --branch V21.3 'https://github.com/nanocurrency/nano-node' .
  git submodule update --init --depth 1
  mkdir /tmp/boost
  BOOST_ROOT=/tmp/boost bash util/build_prep/bootstrap_boost.sh -m
  cmake . -DACTIVE_NETWORK=nano_test_network -DBOOST_ROOT=/tmp/boost
  make -j2
fi

mkdir data
echo 'rpc.enable = true' > data/config-node.toml
echo 'enable_control = true' > data/config-rpc.toml

./nano_node --daemon --data_path data &

for i in {1..10}; do
  if curl -s '[::1]:45000' --data '{"action":"version"}' >/dev/null 2>&1; then break; fi
  sleep 1
done

wallet="$(curl -s '[::1]:45000' --data '{"action":"wallet_create"}' | jq -r .wallet)"

# Genesis key from https://github.com/nanocurrency/nano-node/blob/V21.3/nano/secure/common.cpp#L30
curl -s '[::1]:45000' --data '{"action":"wallet_add","wallet":"'"$wallet"'","key":"34F0A37AAD20F4A260F0A5B3CB3D7FB50673212263E58A380BC10474BB039CE4"}' >/dev/null
wallet_account="nano_3e3j5tkog48pnny9dmfzj1r16pg8t1e76dz5tmac6iq689wyjfpiij4txtdo"

destination="$(curl -s '[::1]:45000' --data '{"action":"account_create","wallet":"'"$wallet"'"}' | jq -r .account)"
refund="$(curl -s '[::1]:45000' --data '{"action":"account_create","wallet":"'"$wallet"'"}' | jq -r .account)"

cat > "$config_dir/nano.json" << EOF
{
  "rpc_url": "http://[::1]:45000/",
  "destination": "$destination",
  "refund": "$refund",
  "wallet": "$wallet",
  "wallet_account": "$wallet_account"
}
EOF
