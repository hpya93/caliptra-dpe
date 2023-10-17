# Step 1: Install dependencies
install_dependencies:
	sudo apt-get update && \
	sudo apt-get install dh-autoreconf libssl-dev \
		libtasn1-6-dev pkg-config libtpms-dev \
		net-tools iproute2 libjson-glib-dev \
		tar\
		wget\
		git\
		build-essential\
		linux-generic\
		libgnutls28-dev expect gawk socat \
		libseccomp-dev make -y

# Step 2: Run autogen.sh, make, check, and install
run_autogen_and_install:
	git clone https://github.com/stefanberger/swtpm.git; \
	cd swtpm; \
	./autogen.sh --with-openssl --prefix=/usr; \
	make -j4; \
	make -j4 check; \
	sudo make install

# Step 3: Set up TPM-related configuration
setup_tpm:
	mkdir -p /tmp/myvtpm
	sudo modprobe tpm_vtpm_proxy
	sudo swtpm chardev --vtpm-proxy --tpmstate dir=/tmp/myvtpm --tpm2 --ctrl type=tcp,port=2322 

# Step 4: Install tpm2-tss
install_tpm2_tss:
	sudo apt-get install libjson-c-dev libssl-dev libcurl4-gnutls-dev -y
	wget https://github.com/tpm2-software/tpm2-tss/releases/download/3.1.0/tpm2-tss-3.1.0.tar.gz
	tar -xzvf tpm2-tss-3.1.0.tar.gz && cd tpm2-tss-3.1.0/ && ./configure && sudo make install && sudo ldconfig

# Step 5: Install tpm2-tools
install_tpm2_tools:
	sudo apt-get install tpm2-tools

# The 'simulator' target runs all steps in order
simulator: install_dependencies run_autogen_and_install  install_tpm2_tss install_tpm2_tools setup_tpm
