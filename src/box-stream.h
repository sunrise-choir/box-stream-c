#ifndef BOX_STREAM_H
#define BOX_STREAM_H

#include <stdint.h>

#define BS_HEADER_SIZE crypto_secretbox_MACBYTES + sizeof(uint16_t) + crypto_secretbox_MACBYTES
#define BS_MAX_PACKET_SIZE 4096

#endif
