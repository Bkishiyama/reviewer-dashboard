#!/usr/bin/env bash
# setup_iot_bridge.sh
# Tool 1 extension: bridges IoTGoat (VirtualBox Internal Network) into the Mininet/OVS 
# topology so Ryu can observe real attack traffic from an external Kali VM against 
# a real IoTGoat VM.
# PREREQUISITES:
# - Mininet topology.py must already be running (s1/s2/s3 must exist)
# - IoTGoat VM reachable at 192.168.100.2 via enp0s3 (Internal Network)
# - Kali VM reachable at 192.168.200.3 via enp0s9 (separate Internal Network)
# Usage: sudo ./setup_iot_bridge.sh

set -e

IOT_IFACE="enp0s3"
KALI_IFACE="enp0s9"
IOT_SUBNET="192.168.100.211/24"

echo "[*] Checking Mininet switch s3 exists"
if ! sudo ovs-vsctl br-exists s3; then
    echo "[!] s3 not found. Start topology.py first."
    exit 1
fi

echo "[*] Disabling NetworkManager on $IOT_IFACE"
sudo nmcli device set "$IOT_IFACE" managed no || true

echo "[*] Enabling IP forwarding"
sudo sysctl -w net.ipv4.ip_forward=1

echo "[*] Ensuring $IOT_IFACE has no stray IP before bridging"
sudo ip addr flush dev "$IOT_IFACE"

echo "[*] Creating br-iot bridge"
sudo ovs-vsctl --may-exist add-br br-iot
sudo ovs-vsctl --may-exist add-port br-iot "$IOT_IFACE"
sudo ip addr add "$IOT_SUBNET" dev br-iot 2>/dev/null || true
sudo ip link set br-iot up

echo "Connecting br-iot to s3 via patch ports"
sudo ovs-vsctl -- --may-exist add-port s3 patch-to-iot \
    -- set interface patch-to-iot type=patch options:peer=patch-to-s3 \
    -- --may-exist add-port br-iot patch-to-s3 \
    -- set interface patch-to-s3 type=patch options:peer=patch-to-iot

echo "Mirroring br-iot traffic onto the patch (bypasses L2 learning shortcut)"
sudo ovs-vsctl -- --id=@patch-to-s3 get Port patch-to-s3 \
    -- --id=@m create Mirror name=iot-mirror select-all=true output-port=@patch-to-s3 \
    -- set Bridge br-iot mirrors=@m


echo "...Verify..."
sudo ovs-vsctl show
echo -e "🟡 \e[33m Testing with ping 192.168.100.2 from Kali VM.\e[0m"
