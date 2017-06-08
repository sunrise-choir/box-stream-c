#include "box-stream.h"

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <sodium.h>

static uint8_t zeros[sizeof(uint16_t) + crypto_secretbox_MACBYTES];

// wrapping in-place increment of a nonce
static void nonce_inc(uint8_t *nonce)
{
  uint8_t i = crypto_secretbox_NONCEBYTES - 1;

  while (i != UINT8_MAX) {
    nonce[i] += 1;
    if (nonce[i] == 0) {
      i--;
    } else {
      break;
    }
  }
}

// wrapping in-place decrement of a nonce
static void nonce_dec(uint8_t *nonce)
{
  uint8_t i = crypto_secretbox_NONCEBYTES - 1;

  while (i != UINT8_MAX) {
    nonce[i] -= 1;
    if (nonce[i] == UINT8_MAX) {
      i--;
    } else {
      break;
    }
  }
}

// indices into an encrypted packet
#define PACKET_LEN crypto_secretbox_MACBYTES
#define PACKET_MAC PACKET_LEN + sizeof(uint16_t)
#define PACKET_CONTENT PACKET_MAC + crypto_secretbox_MACBYTES

void encrypt_packet(
  uint8_t *out,
  const uint8_t *plain_packet,
  uint16_t packet_len,
  const uint8_t encryption_key[crypto_secretbox_KEYBYTES],
  uint8_t nonce[crypto_secretbox_NONCEBYTES]
)
{
  nonce_inc(nonce);

  crypto_secretbox_easy(out + PACKET_MAC, plain_packet, packet_len, nonce, encryption_key);
  out[PACKET_LEN] = htons(packet_len);

  nonce_dec(nonce);

  crypto_secretbox_easy(out, out + PACKET_LEN, sizeof(uint16_t) + crypto_secretbox_MACBYTES, nonce, encryption_key);

  nonce_inc(nonce);
  nonce_inc(nonce);
}

void final_header(
  uint8_t out[BS_HEADER_SIZE],
  const uint8_t encryption_key[crypto_secretbox_KEYBYTES],
  uint8_t nonce[crypto_secretbox_NONCEBYTES]
)
{
  crypto_secretbox_easy(out, zeros, sizeof(zeros), nonce, encryption_key);
}

BS_Header_Decrypt decrypt_header(
  uint8_t out[sizeof(uint16_t) + crypto_secretbox_MACBYTES],
  uint8_t cypher_header[BS_HEADER_SIZE],
  const uint8_t decryption_key[crypto_secretbox_KEYBYTES],
  uint8_t nonce[crypto_secretbox_NONCEBYTES]
)
{
  if (crypto_secretbox_open_easy(out, cypher_header, BS_HEADER_SIZE, nonce, decryption_key) == -1) {
    return BS_INVALID;
  }

  if (memcmp(out, zeros, sizeof(uint16_t) + crypto_secretbox_MACBYTES) == 0) {
    return BS_FINAL;
  }

  *out = ntohs(*out);
  return BS_DEFAULT;
}

bool decrypt_packet(
  uint8_t *out,
  const uint8_t *cypher_packet,
  uint16_t packet_len,
  const uint8_t mac[crypto_secretbox_MACBYTES],
  const uint8_t decryption_key[crypto_secretbox_KEYBYTES],
  uint8_t nonce[crypto_secretbox_NONCEBYTES]
)
{
  nonce_inc(nonce);

  if (crypto_secretbox_open_detached(out, cypher_packet, mac, packet_len, nonce, decryption_key) == -1) {
    return false;
  }

  nonce_inc(nonce);
  return true;
}
