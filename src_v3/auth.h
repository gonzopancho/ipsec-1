#ifndef __AUTH_H__
#define __AUTH_H__

#include <stdio.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include "sa.h"

#define AUTH_HMAC_MD5		0x00
#define AUTH_HMAC_SHA1		0x01
#define AUTH_KEYED_MD5		0x02
#define AUTH_KEYED_SHA1		0x03
#define AUTH_HMAC_SHA256	0x04
#define AUTH_HMAC_SHA384	0x05
#define AUTH_HMAC_SHA512	0x06
#define AUTH_HMAC_RIPEMD160	0x07
#define AUTH_AES_XCBC_MAC	0x08
#define AUTH_TCP_MD5		0x09

typedef struct 
{
	void(*authenticate)(void* payload, size_t size, unsigned char* result);
} Authentication;

Authentication* get_authentication(int algorithm);

extern SA* current_sa;

#endif 