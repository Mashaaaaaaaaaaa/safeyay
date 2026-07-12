# Maintainer: Mashaaaaaaaaaaa <bzflater@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later

pkgname=safeyay
pkgver=0.1.0
pkgrel=1
pkgdesc='AI-assisted security review wrapper for AUR packages installed by yay'
arch=('any')
url='https://github.com/Mashaaaaaaaaaaa/safeyay'
license=('GPL-3.0-or-later')
depends=('bash' 'coreutils' 'procps-ng' 'python>=3.11' 'yay')
optdepends=(
  'ollama: use locally hosted Ollama models'
  'openai-codex-bin: use the Codex CLI reviewer backend'
  'claude-code: use the Claude Code CLI reviewer backend'
)
source=('safeyay' 'safeyay_scanner.py' 'config.example.toml' 'LICENSE')
sha256sums=(
  '53b595a1611d92300e8c55302c1c3a4bdda2a222461547a1111c3d498d45c895'
  'af1db49faf1522525f2d889523536eafdc29104d5d533f7e338b33a51e39057b'
  'd9c3efb9cdc275636ff373f3bfa4dfc6980ea0c7fd96dd32d569af3bc9dec2be'
  '3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986'
)

package() {
  install -Dm755 "$srcdir/safeyay_scanner.py" \
    "$pkgdir/usr/lib/safeyay/safeyay_scanner.py"

  sed 's|scanner="$root/safeyay_scanner.py"|scanner="/usr/lib/safeyay/safeyay_scanner.py"|' \
    "$srcdir/safeyay" > "$pkgdir/safeyay"
  install -Dm755 "$pkgdir/safeyay" "$pkgdir/usr/bin/safeyay"
  rm "$pkgdir/safeyay"

  install -Dm644 "$srcdir/config.example.toml" \
    "$pkgdir/usr/share/doc/safeyay/config.example.toml"
  install -Dm644 "$srcdir/LICENSE" \
    "$pkgdir/usr/share/licenses/safeyay/LICENSE"
}
