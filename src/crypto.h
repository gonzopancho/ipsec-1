#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stdio.h>
#include <string.h>
#include <openssl/des.h>
#include <openssl/blowfish.h>
#include <openssl/cast.h>
#include <openssl/aes.h>
#include <openssl/camellia.h>
#include <openssl/rand.h>
#include <net/ether.h>
#include "sa.h"
#include "esp.h"

#define CRYPTO_DES_CBC			0x01
#define CRYPTO_3DES_CBC			0x02
#define CRYPTO_BLOWFISH_CBC		0x03
#define CRYPTO_CAST128_CBC		0x04
#define CRYPTO_DES_DERIV		0x05
#define CRYPTO_3DES_DERIV		0x06
#define CRYPTO_RIJNDAEL_CBC		0x07
#define CRYPTO_TWOFISH_CBC		0x08
#define CRYPTO_AES_CTR			0x09
#define CRYPTO_CAMELLIA_CBC		0x10

typedef struct 
{
	void(*encrypt)(void* payload, size_t size);
	void(*decrypt)(void* payload, size_t size);
} Cryptography;

Cryptography* get_cryptography(int algorithm);

void _3des_cbc_decrypt(void* payload, size_t size); 
extern SA* current_sa;
#endif 
