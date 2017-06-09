#ifndef BOX_STREAM_H
#define BOX_STREAM_H

#include <stdint.h>
#include <stdbool.h>
#include <sodium.h>

#define BS_CYPHER_HEADER_SIZE crypto_secretbox_MACBYTES + sizeof(uint16_t) + crypto_secretbox_MACBYTES
#define BS_MAX_PACKET_SIZE 4096

// Writes the encrypted header and payload for a given plaintext packet into `out`.
void encrypt_packet(
  uint8_t *out, // length: BS_CYPHER_HEADER_SIZE + packet_len
  const uint8_t *plain_packet, // the packet to encrypt
  uint16_t packet_len, // length of the packet - at most BS_MAX_PACKET_SIZE
  const uint8_t encryption_key[crypto_secretbox_KEYBYTES],
  uint8_t nonce[crypto_secretbox_NONCEBYTES]
);

// Writes the final header that signals the end of the box stream into `out`.
void final_header(
  uint8_t out[BS_CYPHER_HEADER_SIZE],
  const uint8_t encryption_key[crypto_secretbox_KEYBYTES],
  uint8_t nonce[crypto_secretbox_NONCEBYTES]
);

// The result of decrypting a cypher_header. This is
// crypto_secretbox_MACBYTES smaller than the encrypted header since the leading
// mac is not needed anymore.
typedef struct {
  uint16_t packet_len; // The length of the corresponding packets, at most BS_MAX_PACKET_SIZE
  uint8_t packet_mac[crypto_secretbox_MACBYTES]; // The mac of the corresponding packet.
} BS_Plain_Header;

// Returns whether the given header signals the end of the stream.
bool is_final_header(const BS_Plain_Header *plain_header);

// If this returns true, it decrypts a received header into `out`. Returns false
// if the cyper_header was invalid.
bool decrypt_header(
  BS_Plain_Header *out,
  const uint8_t cypher_header[BS_CYPHER_HEADER_SIZE],
  const uint8_t decryption_key[crypto_secretbox_KEYBYTES],
  uint8_t nonce[crypto_secretbox_NONCEBYTES]
);

// Same as `decrypt_header`, but writes the result into `cypher_header`. If this
// returns true, `cypher_header` can be safely cast to a `(BS_Plain_Header*)`.
bool decrypt_header_inplace(
  uint8_t cypher_header[BS_CYPHER_HEADER_SIZE],
  const uint8_t decryption_key[crypto_secretbox_KEYBYTES],
  uint8_t nonce[crypto_secretbox_NONCEBYTES]
);

// Decrypts a received packet, given a pointer to the corresponding
// plain_header, and writes the result into `out`. Returns false on invalid
// input, in which case the content of `out` is unspecified.
bool decrypt_packet(
  uint8_t *out, // length: cypher_packet->packet_len
  const uint8_t *cypher_packet, // the packet to decrypt
  const BS_Plain_Header *plain_header,
  const uint8_t encryption_key[crypto_secretbox_KEYBYTES],
  uint8_t nonce[crypto_secretbox_NONCEBYTES]
);

// Same as `decrypt_packet`, but writes the result into `cypher_packet`.
bool decrypt_packet_inplace(
  uint8_t *cypher_packet,
  const BS_Plain_Header *plain_header,
  const uint8_t encryption_key[crypto_secretbox_KEYBYTES],
  uint8_t nonce[crypto_secretbox_NONCEBYTES]
);

#endif
