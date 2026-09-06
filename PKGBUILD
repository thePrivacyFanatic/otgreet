pkgname=otgreet-git
pkgver=1
pkgrel=1
pkgdesc='Greetd login screen for AEM setups (git)'
arch=('x86_64')
url='https://github.com/thePrivacyFanatic/otgreet'
source=("git+$url")
license=('GPL')
depends=(
  'greetd'
)
makedepends=('git' 'cargo')
b2sums=("SKIP")

build() {
  cd otgreet
  cargo build --release
}

package() {
  install -Dm755 "$srcdir/otgreet/target/release/otgreet" "$pkgdir/usr/bin/otgreet"
}
