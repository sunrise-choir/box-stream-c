# Box-Stream Crypto

This repository contains a C implementation of the crypto in [box-stream](https://github.com/dominictarr/pull-box-stream). The code only covers the actual crypto part of the protocol (corresponding files in different implementations: [js](https://github.com/dominictarr/pull-box-stream/blob/master/index.js), [g](https://github.com/cryptix/secretstream/blob/master/boxstream/box.go)[o](https://github.com/cryptix/secretstream/blob/master/boxstream/unbox.go), [python](https://github.com/pferreir/PySecretHandshake/blob/master/secret_handshake/boxstream.py)), there's no I/O happening here.

This code depends on libsodium. Before calling any function of this module, call [`sodium_init()`](https://download.libsodium.org/doc/usage/) first.

See `box-stream.h` for the API and `example.c` for a usage example.
