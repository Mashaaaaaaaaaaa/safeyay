#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
prefix=${PREFIX:-"$HOME/.local"}
install -d "$prefix/bin" "$prefix/lib/safeyay" "$prefix/share/doc/safeyay" "$prefix/share/licenses/safeyay"
install -m 755 "$root/lib/safeyay/safeyay_scanner.py" "$prefix/lib/safeyay/safeyay_scanner.py"
install -m 755 "$root/bin/safeyay" "$prefix/bin/safeyay"
install -m 644 "$root/config.example.toml" "$prefix/share/doc/safeyay/config.example.toml"
install -m 644 "$root/LICENSE" "$prefix/share/licenses/safeyay/LICENSE"
printf 'Installed %s/bin/safeyay\n' "$prefix"
