build:
	cargo build --release

install: build
	install -Dm755 target/release/otgreet /usr/bin/otgreet
