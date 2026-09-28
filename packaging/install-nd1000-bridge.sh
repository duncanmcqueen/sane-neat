#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception
# Install the ND-1000 SANE bridge and optionally share it over saned.
#
# The bridge runs Neat's ND-1000 Windows driver through the pe-harness tracer,
# so it needs the DLL extracted from Neat's official ND-1000 driver MSI (see
# re/README.md). The DLL is not part of this project.
#
# Usage: sudo bash packaging/install-nd1000-bridge.sh /path/to/neatadfscanner_x64.dll
#   ND_LAN_CIDR=192.168.1.0/24   subnet allowed to use the shared scanner
#                                (default: this host's primary LAN network)
set -euo pipefail

if [[ $EUID -ne 0 || $# -ne 1 ]]; then
    printf 'Usage: sudo bash %s /path/to/neatadfscanner_x64.dll\n' "$0" >&2
    exit 2
fi
source_dll=$(realpath "$1")
root=$(dirname "$(dirname "$(realpath "$0")")")
[[ -f "$source_dll" ]] || { printf 'Missing DLL: %s\n' "$source_dll" >&2; exit 1; }
[[ -x "$root/re/pe-harness/neatcap" && -f "$root/build/libsane-nd1000.so.1" ]] || {
    printf 'Build first: make && make -C re/pe-harness\n' >&2
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

install -Dm755 "$root/build/libsane-nd1000.so.1" /usr/lib/sane/libsane-nd1000.so.1
ln -sfn libsane-nd1000.so.1 /usr/lib/sane/libsane-nd1000.so
install -Dm755 "$root/re/pe-harness/neatcap" /usr/local/libexec/neatcap
install -Dm644 "$source_dll" /usr/local/lib/nd1000/neatadfscanner_x64.dll
install -Dm644 "$root/packaging/dll.d-nd1000" /etc/sane.d/dll.d/nd1000
install -Dm644 "$root/udev/64-neat-nd1000.rules" /etc/udev/rules.d/64-neat-nd1000.rules
udevadm control --reload-rules

for subnet in 127.0.0.1 100.64.0.0/10 ${lan_cidr:+$lan_cidr}; do
    if ! grep -Fxq "$subnet" /etc/sane.d/saned.conf; then
        printf '%s\n' "$subnet" >> /etc/sane.d/saned.conf
    fi
done
systemctl enable --now saned.socket

printf '\nInstalled ND-1000 bridge. Replug the scanner for the udev rule.\n'
printf 'Local check: scanimage -L\n'
printf 'Remote clients: add this host (LAN or Tailscale IP) to /etc/sane.d/net.conf.\n'
if [[ -n $lan_cidr ]]; then
    printf 'saned allows: 127.0.0.1, %s, 100.64.0.0/10. TCP port 6566.\n' "$lan_cidr"
else
    printf 'saned allows: 127.0.0.1, 100.64.0.0/10. Set ND_LAN_CIDR to allow a LAN.\n'
fi
printf 'If a firewall is active, allow TCP 6566 on the LAN/Tailscale interfaces.\n'
