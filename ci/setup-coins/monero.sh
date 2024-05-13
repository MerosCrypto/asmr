#!/bin/bash
set -euxo pipefail

config_dir="$(pwd)/config"
mkdir -p "$config_dir"

cat > "$config_dir/monero.json" << EOF
{
  "daemon": "http://127.0.0.1:18081",
  "wallet": "http://127.0.0.1:18082",
  "wallet_user": "user",
  "wallet_pass": "pass",
  "destination": "42L9GkQeerChpA4rz4MTagL5mBGbEnvPzWLRL5vfJTr3bd8Diz6okcpd9vkxerLXHADdPMbTW9Xk8JcWj8WbeGEmD3aKdsi",
  "refund": "42L9GkQeerChpA4rz4MTagL5mBGbEnvPzWLRL5vfJTr3bd8Diz6okcpd9vkxerLXHADdPMbTW9Xk8JcWj8WbeGEmD3aKdsi"
}
EOF
