#include "box-stream.h"

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sodium.h>

static uint8_t encryption_key[crypto_secretbox_KEYBYTES];
static uint8_t decryption_key[crypto_secretbox_KEYBYTES];

void test_encryption()
{
  const uint8_t encryption_key[crypto_secretbox_KEYBYTES] = {162,29,153,150,123,225,10,173,175,201,160,34,190,179,158,14,176,105,232,238,97,66,133,194,250,148,199,7,34,157,174,24};
  uint8_t encryption_nonce[crypto_secretbox_NONCEBYTES] = {44,140,79,227,23,153,202,203,81,40,114,59,56,167,63,166,201,9,50,152,0,255,226,147};

  const uint8_t plain1[8] = {0, 1, 2, 3, 4, 5, 6, 7};
  const uint8_t plain2[8] = {7, 6, 5, 4, 3, 2, 1, 0};

  const uint8_t expected_header1[BS_CYPHER_HEADER_SIZE] = {181,28,106,117,226,186,113,206,135,153,250,54,221,225,178,211,144,190,14,102,102,246,118,54,195,34,174,182,190,45,129,48,96,193};
  const uint8_t expected_packet1[sizeof(plain1)] = {231,234,80,195,113,173,5,158};
  const uint8_t expected_header2[BS_CYPHER_HEADER_SIZE] = {227,230,249,230,176,170,49,34,220,29,156,118,225,243,7,3,163,197,125,225,240,111,195,126,240,148,201,237,158,158,134,224,246,137};
  const uint8_t expected_packet2[sizeof(plain2)] = {22,134,141,191,19,113,211,114};
  const uint8_t expected_final_header[BS_CYPHER_HEADER_SIZE] = {10,48,84,111,103,103,35,162,175,78,189,58,240,250,196,226,194,197,87,73,119,174,129,124,225,30,3,26,37,221,87,213,153,123};

  uint8_t cyphertext[BS_CYPHER_HEADER_SIZE + BS_MAX_PACKET_SIZE];

  bs_encrypt_packet(cyphertext, plain1, sizeof(plain1), encryption_key, encryption_nonce);
  assert(memcmp(cyphertext, expected_header1, sizeof(expected_header1)) == 0);
  assert(memcmp(cyphertext + sizeof(expected_header1), expected_packet1, sizeof(expected_packet1)) == 0);

  bs_encrypt_packet(cyphertext, plain2, sizeof(plain2), encryption_key, encryption_nonce);
  assert(memcmp(cyphertext, expected_header2, sizeof(expected_header2)) == 0);
  assert(memcmp(cyphertext + sizeof(expected_header2), expected_packet2, sizeof(expected_packet1)) == 0);

  bs_final_header(cyphertext, encryption_key, encryption_nonce);
  assert(memcmp(cyphertext, expected_final_header, sizeof(expected_final_header)) == 0);
}

void test_decryption()
{
  const uint8_t decryption_key[crypto_secretbox_KEYBYTES] = {162,29,153,150,123,225,10,173,175,201,160,34,190,179,158,14,176,105,232,238,97,66,133,194,250,148,199,7,34,157,174,24};
  uint8_t decryption_nonce[crypto_secretbox_NONCEBYTES] = {44,140,79,227,23,153,202,203,81,40,114,59,56,167,63,166,201,9,50,152,0,255,226,147};

  const uint8_t header1[BS_CYPHER_HEADER_SIZE] = {181,28,106,117,226,186,113,206,135,153,250,54,221,225,178,211,144,190,14,102,102,246,118,54,195,34,174,182,190,45,129,48,96,193};
  const uint8_t packet1[8] = {231,234,80,195,113,173,5,158};
  const uint8_t header2[BS_CYPHER_HEADER_SIZE] = {227,230,249,230,176,170,49,34,220,29,156,118,225,243,7,3,163,197,125,225,240,111,195,126,240,148,201,237,158,158,134,224,246,137};
  const uint8_t packet2[8] = {22,134,141,191,19,113,211,114};
  const uint8_t final_header[BS_CYPHER_HEADER_SIZE] = {10,48,84,111,103,103,35,162,175,78,189,58,240,250,196,226,194,197,87,73,119,174,129,124,225,30,3,26,37,221,87,213,153,123};

  const uint8_t expected_plain1[8] = {0, 1, 2, 3, 4, 5, 6, 7};
  const uint8_t expected_plain2[8] = {7, 6, 5, 4, 3, 2, 1, 0};

  BS_Plain_Header plain_header;
  uint8_t plain[8];

  assert(bs_decrypt_header(&plain_header, header1, decryption_key, decryption_nonce) == true);
  assert(bs_is_final_header(&plain_header) == false);
  assert(bs_decrypt_packet(plain, packet1, &plain_header, decryption_key, decryption_nonce) == true);
  assert(memcmp(plain, expected_plain1, sizeof(expected_plain1)) == 0);

  assert(bs_decrypt_header(&plain_header, header2, decryption_key, decryption_nonce) == true);
  assert(bs_is_final_header(&plain_header) == false);
  assert(bs_decrypt_packet(plain, packet2, &plain_header, decryption_key, decryption_nonce) == true);
  assert(memcmp(plain, expected_plain2, sizeof(expected_plain2)) == 0);

  assert(bs_decrypt_header(&plain_header, final_header, decryption_key, decryption_nonce) == true);
  assert(bs_is_final_header(&plain_header) == true);
}

void test_inplace_decryption()
{
  const uint8_t decryption_key[crypto_secretbox_KEYBYTES] = {162,29,153,150,123,225,10,173,175,201,160,34,190,179,158,14,176,105,232,238,97,66,133,194,250,148,199,7,34,157,174,24};
  uint8_t decryption_nonce[crypto_secretbox_NONCEBYTES] = {44,140,79,227,23,153,202,203,81,40,114,59,56,167,63,166,201,9,50,152,0,255,226,147};

  uint8_t header1[BS_CYPHER_HEADER_SIZE] = {181,28,106,117,226,186,113,206,135,153,250,54,221,225,178,211,144,190,14,102,102,246,118,54,195,34,174,182,190,45,129,48,96,193};
  uint8_t packet1[8] = {231,234,80,195,113,173,5,158};
  uint8_t header2[BS_CYPHER_HEADER_SIZE] = {227,230,249,230,176,170,49,34,220,29,156,118,225,243,7,3,163,197,125,225,240,111,195,126,240,148,201,237,158,158,134,224,246,137};
  uint8_t packet2[8] = {22,134,141,191,19,113,211,114};
  uint8_t final_header[BS_CYPHER_HEADER_SIZE] = {10,48,84,111,103,103,35,162,175,78,189,58,240,250,196,226,194,197,87,73,119,174,129,124,225,30,3,26,37,221,87,213,153,123};

  const uint8_t expected_plain1[8] = {0, 1, 2, 3, 4, 5, 6, 7};
  const uint8_t expected_plain2[8] = {7, 6, 5, 4, 3, 2, 1, 0};

  assert(bs_decrypt_header_inplace(header1, decryption_key, decryption_nonce) == true);
  assert(bs_is_final_header((BS_Plain_Header*)header1) == false);
  assert(bs_decrypt_packet_inplace(packet1, (BS_Plain_Header*)header1, decryption_key, decryption_nonce) == true);
  assert(memcmp(packet1, expected_plain1, sizeof(expected_plain1)) == 0);

  assert(bs_decrypt_header_inplace(header2, decryption_key, decryption_nonce) == true);
  assert(bs_is_final_header((BS_Plain_Header*)header2) == false);
  assert(bs_decrypt_packet_inplace(packet2, (BS_Plain_Header*)header2, decryption_key, decryption_nonce) == true);
  assert(memcmp(packet2, expected_plain2, sizeof(expected_plain2)) == 0);

  assert(bs_decrypt_header_inplace(final_header, decryption_key, decryption_nonce) == true);
  assert(bs_is_final_header((BS_Plain_Header*)final_header) == true);
}

void test_nounce_boundaries()
{
  uint8_t encryption_nonce[crypto_secretbox_NONCEBYTES] = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 253, 0};
  uint8_t decryption_nonce[crypto_secretbox_NONCEBYTES];
  memcpy(decryption_nonce, encryption_nonce, crypto_secretbox_NONCEBYTES);

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

void test_invalid_header_decrypt()
{
  uint8_t cypher_header[BS_CYPHER_HEADER_SIZE];
  randombytes_buf(cypher_header, sizeof(cypher_header));

  uint8_t decryption_key[crypto_secretbox_KEYBYTES];
  randombytes_buf(decryption_key, sizeof(decryption_key));

  uint8_t decryption_nonce[crypto_secretbox_NONCEBYTES];
  randombytes_buf(decryption_nonce, sizeof(decryption_nonce));

  BS_Plain_Header plain_header;

  assert(bs_decrypt_header(&plain_header, cypher_header, decryption_key, decryption_nonce) == false);
  assert(bs_decrypt_header_inplace(cypher_header, decryption_key, decryption_nonce) == false);
}

void test_invalid_packet_decrypt()
{
  const uint8_t decryption_key[crypto_secretbox_KEYBYTES] = {162,29,153,150,123,225,10,173,175,201,160,34,190,179,158,14,176,105,232,238,97,66,133,194,250,148,199,7,34,157,174,24};
  uint8_t decryption_nonce[crypto_secretbox_NONCEBYTES] = {44,140,79,227,23,153,202,203,81,40,114,59,56,167,63,166,201,9,50,152,0,255,226,147};

  const uint8_t header1[BS_CYPHER_HEADER_SIZE] = {181,28,106,117,226,186,113,206,135,153,250,54,221,225,178,211,144,190,14,102,102,246,118,54,195,34,174,182,190,45,129,48,96,193};
  uint8_t packet1[8] = {0,0,0,0,113,173,5,158};

  BS_Plain_Header plain_header;

  assert(bs_decrypt_header(&plain_header, header1, decryption_key, decryption_nonce) == true);
  assert(bs_is_final_header(&plain_header) == false);
  assert(bs_decrypt_packet_inplace(packet1, &plain_header, decryption_key, decryption_nonce) == false);
}

int main()
{
  assert(sodium_init() != -1);

  randombytes_buf(encryption_key, sizeof encryption_key);
  memcpy(decryption_key, encryption_key, sizeof(encryption_key));

  test_encryption();
  test_decryption();
  test_inplace_decryption();
  test_nounce_boundaries();
  test_invalid_header_decrypt();
  test_invalid_packet_decrypt();
}
