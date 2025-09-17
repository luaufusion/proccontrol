all:
	cargo build --release
	# set setuid bit and change owner to root
	sudo chown root:root target/release/proccontrol
	sudo chmod u+s target/release/proccontrol