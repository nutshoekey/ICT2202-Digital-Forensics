## Installation
### tpm2-tss
`$ sudo apt -y update`
`$ sudo apt -y install autoconf-archive libcmocka0 libcmocka-dev procps iproute2 build-essential git pkg-config gcc libtool automake libssl-devuthash-dev autoconf doxygen libjson-c-dev libini-config-dev libcurl4-openssl-dev libltdl-dev`
`$ git clone https://github.com/tpm2-software/tpm2-tss`
` cd tpm2-tss`
`./bootstrap`
`./configure --with-udevrulesdir=/etc/udev/rules.d --with-udevrulesprefix`
`make -j$(nproc)`
`make check`
`sudo make install`
