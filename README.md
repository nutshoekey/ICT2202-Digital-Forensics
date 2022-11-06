# ICT2202 Bonk
## System Integrity Using TPM

Bonk is a System Integrity software utilising IMA (Integrity Measurement Architecture) and TPM (Trusted Platform Module) for Linux based systems.

This project is a Proof of Concept (PoC) and is NOT for production use.

## Usage 
`gcc poc.c -ltss2-esys -ltss2-fapi -lcrypto -o poc`
`sudo ./poc`

You can also run the compiled `poc` file inside this repository.

## Features
- Provision the system in a trusted state
- Verify that the system is still in a trusted state

## Dependencies
- tpm2-tss (https://github.com/tpm2-software/tpm2-tss)
- openssl (https://github.com/openssl/openssl)

## Authors
- He Haiqi (2102948@sit.singaporetech.edu.sg) [nutshoekey]
- Adriel Koh Guang Hui (2101296@sit.singaporetech.edu.sg) [adriel723]
- Shathiya Sulthana D/O Shajahan (2102605@sit.singaporetech.edu.sg) [shathicurri01]
- Chee Wei Lun Kenneth (2100788@sit.singaporetech.edu.sg) [kennethCWL]
