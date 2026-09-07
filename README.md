# otgreet

A greeter for auto-unlock AEM setups.
For manual unlock there's [tpm2-totp](https://github.com/tpm2-software/tpm2-totp).

Disclaimer: this is more of a proof-of-concept,
modern UEFI secure boot is absolutely horrible at resisting sophisticated
attacks by itself, while [the well though-out solutions](https://github.com/linuxboot/heads)
already have this as a feature (though non are auto-unlock as of now for simplicity),
and hardware-security-enforcing DRTM loaders like [tboot](https://sourceforge.net/projects/tboot/)
have almost no documentation.

I would only treat this as a serious project when an actual threat model uses this.
Until then expect the lack of support for AEM USB drives and for qr code generation.

## building

On arch download the PKGBUILD into an empty directory and run `makepkg -si` in it

Otherwise clone the repo, then run `make install` to build and install to `/usr/bin`

## usage

Running `otgreet init` creates a TOTP secret at `/etc/greetotp` and prints the
otpauth url to stdout

Running `otgreet greet` displays the UI when using a debug build, release builds
panic without a greetd socket to connect to
