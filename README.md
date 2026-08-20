# otgreet
a greeter with the same features of [tpm2-totp](https://github.com/tpm2-software/tpm2-totp)

this is more of a proof-of-concept, modern UEFI secure boot is absolutely horrible at resisting any attack that was formulated before its creation and [the well though-out mechanisms](https://github.com/linuxboot/heads) have already added this as a feature.

basically I would only treat this as a serious project when an actual threat model has a use for this.

## building
clone the repo, then run `make install` to build and install to `/usr/bin`

## usage
running `otgreet init` creates a TOTP secret at `/etc/greetotp` and prints it
running `otgreet` otherwise just displays the UI (the reboot and shutdown functions currently require logind)
