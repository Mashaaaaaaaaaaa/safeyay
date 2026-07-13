# Maintainer: Mashaaaaaaaaaaa <bzflater@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later

pkgname=safeyay
pkgver=0.2.6
pkgrel=1
pkgdesc='AI-assisted security review wrapper for AUR packages installed by yay'
arch=('any')
url='https://github.com/Mashaaaaaaaaaaa/safeyay'
license=('GPL-3.0-or-later')
depends=('bash' 'coreutils' 'procps-ng' 'python>=3.11' 'yay')
optdepends=(
  'ollama: use locally hosted Ollama models'
  'openai-codex: use the Codex CLI reviewer backend'
  'claude-code: use the Claude Code CLI reviewer backend'
  'ks-aur-scanner: independent first-pass AUR security scan'
  'clamav: independent malware-signature pre-scan'
)
source=("$pkgname-$pkgver-runtime.tar.gz::$url/releases/download/v$pkgver/$pkgname-$pkgver-runtime.tar.gz")
sha256sums=('992e063f8e6abc79b58236722675ae0ddc47769819c2857881fbd158ae2756d4')

package() {
  cd "$pkgname-$pkgver"

  install -Dm755 lib/safeyay/safeyay_scanner.py \
    "$pkgdir/usr/lib/safeyay/safeyay_scanner.py"

  install -Dm755 bin/safeyay "$pkgdir/usr/bin/safeyay"

  install -Dm644 config.example.toml \
    "$pkgdir/usr/share/doc/safeyay/config.example.toml"
  install -Dm644 LICENSE \
    "$pkgdir/usr/share/licenses/safeyay/LICENSE"
}
