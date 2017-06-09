#include "box-stream.h"

#include <assert.h>
#include <string.h>

int main()
{
  assert(sodium_init() != -1);

  uint8_t encryption_nonce[crypto_secretbox_NONCEBYTES];
  randombytes_buf(encryption_nonce, sizeof(encryption_nonce));
  uint8_t decryption_nonce[crypto_secretbox_NONCEBYTES];
  memcpy(decryption_nonce, encryption_nonce, sizeof(encryption_nonce));

  uint8_t encryption_key[crypto_secretbox_KEYBYTES];
  randombytes_buf(encryption_key, sizeof(encryption_key));
  uint8_t decryption_key[crypto_secretbox_KEYBYTES];
  memcpy(decryption_key, encryption_key, sizeof(encryption_key));

  uint8_t plaintext[BS_MAX_PACKET_SIZE];
  uint8_t cyphertext[BS_CYPHER_HEADER_SIZE + BS_MAX_PACKET_SIZE];
  BS_Plain_Header plain_header;
  uint8_t decrypted_packet[BS_MAX_PACKET_SIZE];

  int i;
  for (i = 0; i < 10000; i++) {
    uint16_t plaintext_len = 8;
    randombytes_buf(plaintext, plaintext_len);

    bs_encrypt_packet(cyphertext, plaintext, plaintext_len, encryption_key, encryption_nonce);

    assert(bs_decrypt_header(&plain_header, cyphertext, decryption_key, decryption_nonce) == true);
    assert(bs_is_final_header(&plain_header) == false);
    assert(plain_header.packet_len == plaintext_len);

    assert(bs_decrypt_packet(decrypted_packet, cyphertext + BS_CYPHER_HEADER_SIZE, &plain_header, decryption_key, decryption_nonce) == true);

    assert(memcmp(decrypted_packet, plaintext, plaintext_len) == 0);
  }
}
