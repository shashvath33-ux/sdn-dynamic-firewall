#!/usr/bin/env bash
# One-time setup on Ubuntu 20.04 / 22.04 / 24.04 (VM or native).  Needs sudo + internet.
#   bash setup_ubuntu.sh
# Installs Mininet + Open vSwitch from apt, and Ryu in its own Python 3.9 virtualenv
# (~/ryu-venv). Ryu does not install on Python >= 3.11, so a private 3.9 is used
# on every Ubuntu version; nothing system-wide is downgraded.
set -euo pipefail

echo "[1/4] apt packages"
sudo apt-get update
sudo apt-get install -y mininet openvswitch-switch ethtool iproute2 iputils-ping \
     net-tools python3 python3-pip git

echo "[2/4] Open vSwitch service"
sudo systemctl enable --now openvswitch-switch 2>/dev/null || sudo service openvswitch-switch start
sudo ovs-vsctl show >/dev/null && echo "  OVS is running"
if ! sudo modprobe openvswitch 2>/dev/null; then
  echo "  NOTE: kernel module 'openvswitch' not available -> always add  --datapath user  to"
  echo "        topology.py / run_experiments.py (slower, functionally identical)."
fi

echo "[3/4] uv (to fetch Python 3.9)"
if ! command -v uv >/dev/null 2>&1; then
  python3 -m pip install --user --quiet uv 2>/dev/null \
    || python3 -m pip install --user --quiet --break-system-packages uv
  export PATH="$HOME/.local/bin:$PATH"
fi

echo "[4/4] Ryu in ~/ryu-venv (Python 3.9)"
uv venv --python 3.9 "$HOME/ryu-venv"
uv pip install --python "$HOME/ryu-venv/bin/python" -q "setuptools==57.5.0" wheel pbr
uv pip install --python "$HOME/ryu-venv/bin/python" -q --no-build-isolation \
    ryu "eventlet==0.30.2" "dnspython<2"
"$HOME/ryu-venv/bin/python" -c "import ryu; print('  Ryu import OK')"

echo
echo "Done. Quick checks:"
echo "  sudo mn --test pingall"
echo "  ~/ryu-venv/bin/python tests/test_controller_logic.py"
