prog := conan
server := conan-server

install_path := /usr/bin/

default: install

compile:
	export "CARGO_PROFILE_RELEASE_LTO=off" && cargo build --release

copy:
	echo "Installing to $(install_path)"
	./install.sh


install: compile copy
