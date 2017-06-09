#ifndef BOX_STREAM_H
#define BOX_STREAM_H

#include <stdint.h>
#include <stdbool.h>
#include <sodium.h>

#define BS_HEADER_SIZE crypto_secretbox_MACBYTES + sizeof(uint16_t) + crypto_secretbox_MACBYTES
#define BS_PLAIN_HEADER_SIZE sizeof(uint16_t) + crypto_secretbox_MACBYTES
#define BS_MAX_PACKET_SIZE 4096

// Writes the encrypted header and payload for a given plaintext packet into `out`.
void encrypt_packet(
  uint8_t *out, // length: BS_HEADER_SIZE + packet_len
  const uint8_t *plain_packet, // the packet to encrypt
  uint16_t packet_len, // length of the packet - at most BS_MAX_PACKET_SIZE
  const uint8_t encryption_key[crypto_secretbox_KEYBYTES],
  uint8_t nonce[crypto_secretbox_NONCEBYTES]
);

// Writes the final header that signals the end of the box stream into `out`.
void final_header(
  uint8_t out[BS_HEADER_SIZE],
  const uint8_t encryption_key[crypto_secretbox_KEYBYTES],
  uint8_t nonce[crypto_secretbox_NONCEBYTES]
);

// The result of decrypting a header.
typedef enum {
  BS_INVALID, // The header was not authenticated correctly or could be decrypted.
  BS_FINAL, // The header signals the end of the box stream.
  BS_DEFAULT // A normal header which should be followed by an encrypted packet.
} BS_Header_Decrypt;

// Decrypts a received header into `plain_header`, if this returns BS_DEFAULT.
BS_Header_Decrypt decrypt_header(
  uint8_t plain_header[BS_PLAIN_HEADER_SIZE],
  const uint8_t cypher_header[BS_HEADER_SIZE],
  const uint8_t decryption_key[crypto_secretbox_KEYBYTES],
  uint8_t nonce[crypto_secretbox_NONCEBYTES]
);

// Decrypts a received packet, given a pointer to the corresponding
// plain_header, and writes the result into `out`. Returns false on invalid
// input, in which case the content of `out` is unspecified.
bool decrypt_packet(
  uint8_t *out, // length: packet_len
  const uint8_t *cypher_packet, // the packet to decrypt
  uint16_t packet_len, // length of the packet - at most BS_MAX_PACKET_SIZE
  const uint8_t mac[crypto_secretbox_MACBYTES], // mac to decrypt cypher_packet
  const uint8_t encryption_key[crypto_secretbox_KEYBYTES],
  uint8_t nonce[crypto_secretbox_NONCEBYTES]
);

// TODO add type for plain header

#endif
