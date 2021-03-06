#include "auth.h"

static void _hmac_md5(void* payload, size_t size, unsigned char* result) 
{
	unsigned char* temp = (unsigned char*)malloc(16);
	temp = HMAC(EVP_md5(), &(current_sa->esp_auth_key), 16, payload, size , NULL, NULL);
	memcpy(result, temp, 12);
}

static void _hmac_sha1(void* payload, size_t size, unsigned char* result) 
{
	unsigned char* temp = (unsigned char*)malloc(20);
	temp = HMAC(EVP_sha1(), &(current_sa->esp_auth_key), 20, payload, size , NULL, NULL);

	memcpy(result, temp, 12);
}
/*
   Not implemented : No RFC
*/
static void _keyed_md5(void* payload, size_t size, unsigned char* result) 
{
}
static void _keyed_sha1(void* payload, size_t size, unsigned char* result) 
{
}

static void _hmac_sha256(void* payload, size_t size, unsigned char* result) 
{
	unsigned char* temp = (unsigned char*)malloc(32);
	temp = HMAC(EVP_sha256(), &(current_sa->esp_auth_key), 32, payload, size , NULL, NULL);

	memcpy(result, temp, 12);
}
/*
	TODO : Debug for 384, 512
*/
static void _hmac_sha384(void* payload, size_t size, unsigned char* result) 
{
	unsigned char* temp = (unsigned char*)malloc(48);
	temp = HMAC(EVP_sha384(), &(current_sa->esp_auth_key), 48, payload, size , NULL, NULL);

	memcpy(result, temp, 12);
}
static void _hmac_sha512(void* payload, size_t size, unsigned char* result) 
{
	unsigned char* temp = (unsigned char*)malloc(64);
	temp = HMAC(EVP_sha512(), &(current_sa->esp_auth_key), 64, payload, size , NULL, NULL);

	memcpy(result, temp, 12);
}
static void _hmac_ripemd160(void* payload, size_t size, unsigned char* result) 
{
	unsigned char* temp = (unsigned char*)malloc(20);
	temp = HMAC(EVP_ripemd160(), &(current_sa->esp_auth_key), 20, payload, size , NULL, NULL);

	memcpy(result, temp, 12);
}
/*
   Not implemented : No openssl function

	   AES-XCBC-MAC is not directly supported. However, it's very simple to
	   implement as it's based on AES-CBC for which there is support.
*/
static void _aes_xcbc_mac(void* payload, size_t size, unsigned char* result) 
{
}
/* 
   Not implemented : Only for BSD
*/
static void _tcp_md5(void* payload, size_t size, unsigned char* result) 
{
}

Authentication authentications[] =
{
	{.authenticate = _hmac_md5},
	{.authenticate = _hmac_sha1},
	{.authenticate = _keyed_md5},
	{.authenticate = _keyed_sha1},
	{.authenticate = _hmac_sha256},
	{.authenticate = _hmac_sha384},
	{.authenticate = _hmac_sha512},
	{.authenticate = _hmac_ripemd160},
	{.authenticate = _aes_xcbc_mac},
	{.authenticate = _tcp_md5},
};

Authentication* get_authentication(int algorithm) 
{
	return &authentications[algorithm - 1];
}

