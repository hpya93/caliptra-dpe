# DPE Verification Tests

This test suite is a userspace test-suite which exercises DPE commands end-to-end and ensures compliance with the DPE iRoT Profile.
The following configuration is required to run a specific test that verifies Caliptra DPE flow with TPM emulator.

## Install dependencies
Install the dependencies for software TPM installation. 
```sh
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
```
## Build TPM emulator
Run autogen.sh, make, check, and install
```sh
git clone https://github.com/stefanberger/swtpm.git; \
cd swtpm; \
./autogen.sh --with-openssl --prefix=/usr; \
make -j4; \
make -j4 check; \
sudo make install
```
## Install TPM tools
- Install_tpm2_tss
```sh
sudo apt-get install libjson-c-dev libssl-dev libcurl4-gnutls-dev -y
wget https://github.com/tpm2-software/tpm2-tss/releases/download/3.1.0/tpm2-tss-3.1.0.tar.gz
tar -xzvf tpm2-tss-3.1.0.tar.gz && cd tpm2-tss-3.1.0/ && ./configure && sudo make install && sudo ldconfig
```
- Install tpm2-tools
```sh
sudo apt-get install tpm2-tools
```
Users have the option to execute the above instructions either manually or by using the 'make simulator' command. To set up and run the TPM emulator, it's necessary to clear the TPM files from the '/dev/tpm' directory before starting the emulator.

## Remove TPM files
```sh
sudo rm -f /dev/tpm0 /dev/tpmrm0
```
## Install and run TPM emulator
- Configure and run software TPM
```sh
mkdir -p /tmp/myvtpm
sudo modprobe tpm_vtpm_proxy
sudo swtpm chardev --vtpm-proxy --tpmstate dir=/tmp/myvtpm --tpm2 --ctrl type=tcp,port=2322     
```
## Run test
- Open another instance of terminal.
- Run the go tests
```sh
cd caliptra-dpe/verification
go test .
```
Run the above instructions using 'make simulator' command without doing it manually._
