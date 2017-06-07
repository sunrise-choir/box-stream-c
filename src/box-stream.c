#include "box-stream.h"

#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sodium.h>

static uint8_t zeros[sizeof(uint16_t) + crypto_secretbox_MACBYTES];

typedef struct {
  uint8_t header_mac[crypto_secretbox_MACBYTES];
  uint16_t length; // at most BS_MAX_PACKET_SIZE
  uint8_t packet_mac[crypto_secretbox_MACBYTES];
} BS_Header;

// TODO could use a nonce_decrement function to only need one nonce
typedef struct {
  const uint8_t *encryption_key; // length: crypto_secretbox_KEYBYTES
  uint8_t nonce1[crypto_secretbox_NONCEBYTES];
  uint8_t nonce2[crypto_secretbox_NONCEBYTES];
} BS_Boxer;

// wrapping in-place increment of a nonce
static void nonce_inc(uint8_t *nonce)
{
  sodium_increment(nonce, crypto_secretbox_NONCEBYTES);
}

// writes header and payload for a given plaintext packet into `out`
void encrypt_packet(
  uint8_t *out, // length: BS_HEADER_SIZE + packet_len
  const uint8_t *plain_packet, // the packet to encrypt
  uint16_t packet_len, // length of the packet - at most BS_MAX_PACKET_SIZE
  BS_Boxer *state
)
{
  BS_Header *header = (BS_Header *)out;

  nonce_inc(state->nonce2);

  crypto_secretbox_easy(header->packet_mac, plain_packet, packet_len, state->nonce2, state->encryption_key);
  header->length = htons(packet_len);

  crypto_secretbox_easy((uint8_t *)header, (uint8_t *)&header->length, sizeof(uint16_t) + crypto_secretbox_MACBYTES, state->nonce1, state->encryption_key);

  nonce_inc(state->nonce2);
  nonce_inc(state->nonce1);
  nonce_inc(state->nonce1);
}

// writes the final header corresponding to the secret key and current nonce into out
void final_header(
  uint8_t out[BS_HEADER_SIZE],
  BS_Boxer *state
)
{
  crypto_secretbox_easy(out, zeros, sizeof(zeros), state->nonce1, state->encryption_key);
}

// // takes an encrypted cyphertext and writes the decrypted plaintext into `out`
// // returns false on invalid input, in which case the content of `out` is unspecified
// bool decrypt_packet(
//   uint8_t *out, // length: packet_len - BS_HEADER_SIZE
//   const uint8_t *cypher_packet, // the packet to decrypt
//   uint16_t packet_len, // length of the packet - at least BS_HEADER_SIZE, at most BS_MAX_PACKET_SIZE + BS_HEADER_SIZE
//   BS_Boxer *state
// )
// {
//
// }
