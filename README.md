# otgreet
a greeter with the same features of [tpm2-totp](https://github.com/tpm2-software/tpm2-totp), but for auto-unlock setups.

this is more of a proof-of-concept, modern UEFI secure boot is absolutely horrible at resisting attack vectors by itself, with [the well though-out solutions](https://github.com/linuxboot/heads) already having this as a feature (though I do not know of an auto-unlock method for this), and replacements such as intel TXT are too badly documented to practically set up.


basically I would only treat this as a serious project when an actual threat model has a use for this.
until then expect the stub error handeling and lack of support for AEM USB drives.

## building
clone the repo, then run `make install` to build and install to `/usr/bin`

## usage
running `otgreet init` creates a TOTP secret at `/etc/greetotp` and prints it
running `otgreet` otherwise just displays the UI (the reboot and shutdown functions currently require logind)
