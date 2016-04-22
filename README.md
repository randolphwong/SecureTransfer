# SecureTransfer

A file transfer application that improves data authenticity and confidentiality.

Data authenticity is achieved with RSA encryption, while confidentiality is
achieved with either RSA or AES encryption. Naturally, RSA file encryption will
be much slower than the AES counterpart.

## Installation

`./gradlew build`

## How to use

`./startserver [aes rsa]`

`./startclient [aes rsa] filename`

