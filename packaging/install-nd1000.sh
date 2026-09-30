#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception
# Install the native ND-1000 SANE backend and share it over saned.
#
# The backend links src/nd1000.c and needs no vendor driver at run time.
#
# Usage: sudo bash packaging/install-nd1000.sh
#   ND_LAN_CIDR=192.168.1.0/24   subnet allowed to use the shared scanner
#                                (default: this host's primary LAN network)
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    printf 'Usage: sudo bash %s\n' "$0" >&2
    exit 2
fi
root=$(dirname "$(dirname "$(realpath "$0")")")
[[ -f "$root/build/libsane-nd1000.so.1" ]] || {
    printf 'Build first: make\n' >&2
    exit 1
}

lan_cidr=${ND_LAN_CIDR:-}
if [[ -z $lan_cidr ]]; then
    addr=$(ip -o -4 addr show scope global 2>/dev/null | awk 'NR==1 {print $4}')
    if [[ -n $addr ]] && command -v python3 >/dev/null; then
        lan_cidr=$(python3 -c 'import ipaddress,sys; print(ipaddress.ip_network(sys.argv[1], strict=False))' \
                   "$addr" 2>/dev/null || true)
    fi
fi
if [[ -n $lan_cidr ]]; then
    [[ $lan_cidr =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/([0-9]|[12][0-9]|3[0-2])$ ]] || {
        printf 'Invalid LAN CIDR: %s\n' "$lan_cidr" >&2
        exit 2
    }
fi

sane_dir=/usr/lib/sane
[[ -d /usr/lib64/sane ]] && sane_dir=/usr/lib64/sane
install -Dm755 "$root/build/libsane-nd1000.so.1" "$sane_dir/libsane-nd1000.so.1"
ln -sfn libsane-nd1000.so.1 "$sane_dir/libsane-nd1000.so"
if [[ -x "$root/build/nd1000-scan" ]]; then
    install -Dm755 "$root/build/nd1000-scan" /usr/local/bin/nd1000-scan
fi
install -Dm644 "$root/packaging/dll.d-nd1000" /etc/sane.d/dll.d/nd1000
install -Dm644 "$root/udev/64-neat-nd1000.rules" /etc/udev/rules.d/64-neat-nd1000.rules
udevadm control --reload-rules

for subnet in 127.0.0.1 100.64.0.0/10 ${lan_cidr:+$lan_cidr}; do
    if ! grep -Fxq "$subnet" /etc/sane.d/saned.conf; then
        printf '%s\n' "$subnet" >> /etc/sane.d/saned.conf
    fi
done
systemctl enable --now saned.socket

printf '\nInstalled native ND-1000 backend. Replug the scanner for the udev rule.\n'
printf 'Local check: scanimage -L\n'
printf 'Remote clients: add this host (LAN or Tailscale IP) to /etc/sane.d/net.conf.\n'
if [[ -n $lan_cidr ]]; then
    printf 'saned allows: 127.0.0.1, %s, 100.64.0.0/10. TCP port 6566.\n' "$lan_cidr"
else
    printf 'saned allows: 127.0.0.1, 100.64.0.0/10. Set ND_LAN_CIDR to allow a LAN.\n'
fi
printf 'If a firewall is active, allow TCP 6566 on the LAN/Tailscale interfaces.\n'
