#include "crypto.h"

// Key Length : 24 Bytes
static void _3des_cbc_encrypt(void* payload, size_t size) 
{
	DES_cblock key1, key2, key3, iv;
	DES_key_schedule ks1, ks2, ks3;

	// 1. Key & IV Extract
	memcpy(key1, &(current_sa->esp_crypto_key[0]), 8);
	memcpy(key2, &(current_sa->esp_crypto_key[1]), 8);
	memcpy(key3, &(current_sa->esp_crypto_key[2]), 8);

	RAND_bytes((unsigned char*)(&(current_sa->iv)), 8);
	memcpy(iv, &(current_sa->iv), 8);

	DES_set_odd_parity(&key1);
	DES_set_odd_parity(&key2);
	DES_set_odd_parity(&key3);

	// Key Validation Check
	if(DES_set_key_checked(&key1, &ks1) ||
	   DES_set_key_checked(&key2, &ks2) ||
	   DES_set_key_checked(&key3, &ks3))
	{
			printf("DES_set_key_checked Error\n");
	}

	DES_ede3_cbc_encrypt((const unsigned char*)payload,
							(unsigned char*)payload, 
							size , &ks1, &ks2, &ks3, &iv, DES_ENCRYPT);
/*
	ESP* esp = (ESP*)payload;
	
	printf("\nEncrypted : \n");
	int i;
	for(i = 1; i < 65; i++)
	{
		printf("%02x ", esp->body[i - 1]);
		if(i % 16 == 0)
				printf("\n");
	}
	printf("\n");
*/

}

void _3des_cbc_decrypt(void* payload, size_t size) 
{
	DES_cblock key1, key2, key3, iv;
	DES_key_schedule ks1, ks2, ks3;

	ESP* esp = (ESP*)payload;
	
	// Key & IV Extract
	memcpy(key1, &(current_sa->esp_crypto_key[0]), 8);
	memcpy(key2, &(current_sa->esp_crypto_key[1]), 8);
	memcpy(key3, &(current_sa->esp_crypto_key[2]), 8);
	memcpy(iv, &(esp->iv), 8);
	
	// Key Validation Check
	DES_set_odd_parity(&key1);
	DES_set_odd_parity(&key2);
	DES_set_odd_parity(&key3);
	
	if(DES_set_key_checked(&key1, &ks1) ||
	   DES_set_key_checked(&key2, &ks2) ||
	   DES_set_key_checked(&key3, &ks3))
	{
			printf("DES_set_key_checked Error\n");
	}

	DES_ede3_cbc_encrypt((const unsigned char*)esp->body, 
							(unsigned char*)esp->body, 
							size , &ks1, &ks2, &ks3, &iv, DES_DECRYPT);
	
/*
	printf("\nDecrypted : \n");
	int i;
	for(i = 1; i < 65; i++)
	{
		printf("%02x ", esp->body[i - 1]);
		if(i % 16 == 0)
				printf("\n");
	}
	printf("\n");
*/
}

// Key Length : 8 Bytes
static void _des_cbc_encrypt(void* payload, size_t size) 
{
	DES_cblock key, iv;
	DES_key_schedule ks; 
	
	memcpy(key, &(current_sa->esp_crypto_key[0]), 8);
	
	RAND_bytes((unsigned char*)(&(current_sa->iv)), 8);
	
	memcpy(iv, &(current_sa->iv), 8);

	DES_set_odd_parity(&key);

	if(DES_set_key_checked(&key, &ks))
	{
		printf("DES_set_key_checked Error\n");
	}
	
	DES_ncbc_encrypt((const unsigned char *)payload, 
			(unsigned char *)payload,
			size, &ks, &iv, DES_ENCRYPT );
	
}

static void _des_cbc_decrypt(void* payload, size_t size) 
{
	DES_cblock key, iv;
	DES_key_schedule ks;

	ESP* esp = (ESP*)payload;

	memcpy(key, &(current_sa->esp_crypto_key[0]), 8);
	memcpy(iv, &(esp->iv), 8);

	DES_set_odd_parity(&key);

	if(DES_set_key_checked(&key, &ks))
	{
		printf("DES_set_key_checked Error\n");
	}

	DES_ncbc_encrypt((const unsigned char *)esp->body, 
			(unsigned char *)esp->body,
			size, &ks, &iv, DES_DECRYPT);
}

// Key Length : 5 ~ 56 Bytes (Default : 16 Bytes)
static void _blowfish_cbc_encrypt(void* payload, size_t size)
{
	BF_KEY* key = calloc(1, sizeof(BF_KEY));
	
	// TODO : Variable Key Length
	BF_set_key(key, 16, (const unsigned char*)(&(current_sa->esp_crypto_key[0])));
	
	RAND_bytes((unsigned char*)(&(current_sa->iv)), 8);
	
	unsigned char iv[8];
	memcpy(iv, &(current_sa->iv), 8);
	
	BF_cbc_encrypt((const unsigned char *)payload, 
			(unsigned char *)payload, 
			size, key, (unsigned char *)iv, BF_ENCRYPT);
/*
	ESP* esp = (ESP*)payload;
	
	printf("\nEncrypted : \n");
	int i;
	for(i = 1; i < 65; i++)
	{
		printf("%02x ", esp->body[i - 1]);
		if(i % 16 == 0)
				printf("\n");
	}
	printf("\n");
*/
}

static void _blowfish_cbc_decrypt(void* payload, size_t size)
{
	BF_KEY* key = calloc(1, sizeof(BF_KEY));
	
	ESP* esp = (ESP*)payload;
	
	// TODO : Variable Key Length
	BF_set_key(key, 16, (const unsigned char*)(&(current_sa->esp_crypto_key[0])));
	
	BF_cbc_encrypt((const unsigned char *)esp->body, 
			(unsigned char *)esp->body, 
			size, key, (unsigned char *)(&(esp->iv)), BF_DECRYPT);
/*
	printf("\nDecrypted : \n");
	int i;
	for(i = 1; i < 65; i++)
	{
		printf("%02x ", esp->body[i - 1]);
		if(i % 16 == 0)
				printf("\n");
	}
	printf("\n");
*/
}

// Key Length : 5 ~ 56 Bytes (Default : 16 Bytes)
static void _cast128_cbc_encrypt(void* payload, size_t size)
{
	CAST_KEY* key = calloc(1, sizeof(CAST_KEY));

	// TODO : Variable Key Length
	CAST_set_key(key, 16, (const unsigned char*)(&(current_sa->esp_crypto_key[0])));

	RAND_bytes((unsigned char*)(&(current_sa->iv)), 8);

	unsigned char iv[8];
	memcpy(iv, &(current_sa->iv), 8);
	
	CAST_cbc_encrypt((const unsigned char *)payload,
			(unsigned char *)payload,
			size, key, (unsigned char *)iv, CAST_ENCRYPT);
/*
	ESP* esp = (ESP*)payload;
	
	printf("\nEncrypted : \n");
	int i;
	for(i = 1; i < 65; i++)
	{
		printf("%02x ", esp->body[i - 1]);
		if(i % 16 == 0)
				printf("\n");
	}
	printf("\n");
*/
}

static void _cast128_cbc_decrypt(void* payload, size_t size)
{
	CAST_KEY* key = calloc(1, sizeof(CAST_KEY));
	
	ESP* esp = (ESP*)payload;
	
	// TODO : Variable Key Length
	CAST_set_key(key, 16, (const unsigned char*)(&(current_sa->esp_crypto_key[0])));
	
	CAST_cbc_encrypt((const unsigned char *)esp->body, 
			(unsigned char *)esp->body, 
			size, key, (unsigned char *)(&(esp->iv)), CAST_DECRYPT);
/*
	printf("\nDecrypted : \n");
	int i;
	for(i = 1; i < 65; i++)
	{
		printf("%02x ", esp->body[i - 1]);
		if(i % 16 == 0)
				printf("\n");
	}
	printf("\n");
*/
}

/*
 	Not implemented : NO RFC

   		This Internet-Draft has been deleted. Unrevised documents placed in the
		Internet-Drafts directories have a maximum life of six months. After
		that time, they are deleted. This Internet-Draft was not published as
		an RFC.

		The name of the internet-draft was draft-ietf-ipsec-ciph-des-derived-00.txt

		Internet-Drafts are not an archival document series, and expired
		drafts, such as this one, are not available; please do not ask for
		copies... they are not available. The Secretariat does not have
		information as to future plans of the authors or working groups WRT the
		deleted Internet-Draft.

		For more information or a copy of the document, contact the author directly.

		Draft Author(s):
		Phil Karn <pkarn@qualcomm.com>,
		William Simpson <wsimpson@greendragon.com>,
		Perry Metzger <perry@piermont.com>
*/
static void _des_deriv_encrypt(void* payload, size_t size)
{}
static void _des_deriv_decrypt(void* payload, size_t size)
{}
static void _3des_deriv_encrypt(void* payload, size_t size)
{}
static void _3des_deriv_decrypt(void* payload, size_t size)
{}

// TODO : 16 Byte Alighment for Payload
// Key Length : 16, 24, 32 Bytes (Default : 16 Bytes)
static void _rijndael_cbc_encrypt(void* payload, size_t size)
{
	AES_KEY* key = calloc(1, sizeof(AES_KEY));

	// TODO : Variable Key Length
	AES_set_encrypt_key((const unsigned char*)(&(current_sa->esp_crypto_key[0])), 128, key);

	RAND_bytes((unsigned char*)(&(current_sa->iv)), 8);

	unsigned char iv[8];
	memcpy(iv, &(current_sa->iv), 8);
	
	AES_cbc_encrypt((const unsigned char *)payload,
			(unsigned char *)payload,
			size, key, (unsigned char *)iv, AES_ENCRYPT);
/*
	ESP* esp = (ESP*)payload;
	printf("\nEncrypted : \n");
	int i;
	for(i = 1; i < 65; i++)
	{
		printf("%02x ", esp->body[i - 1]);
		if(i % 16 == 0)
				printf("\n");
	}
	printf("\n");
*/
}

static void _rijndael_cbc_decrypt(void* payload, size_t size)
{
	AES_KEY* key = calloc(1, sizeof(AES_KEY));
	
	ESP* esp = (ESP*)payload;
	
	unsigned char* iv = (unsigned char*)malloc(8);
	memcpy(iv, &(esp->iv), 8);
	// TODO : Variable Key Length
	AES_set_decrypt_key((const unsigned char*)(&(current_sa->esp_crypto_key[0])), 128, key);
	
	AES_cbc_encrypt((const unsigned char *)esp->body, 
			(unsigned char *)esp->body, 
			size, key, iv, AES_DECRYPT);
/*
	printf("\nDecrypted : \n");
	int i;
	for(i = 1; i < 65; i++)
	{
		printf("%02x ", esp->body[i - 1]);
		if(i % 16 == 0)
				printf("\n");
	}
	printf("\n");
*/
}
/*
   Not implemented : No openssl function 

   AES and Triple DES are considered to be strong. Blowfish is still a good algorithm but its author (Bruce Schneier) recommends that you should use the "twofish" algorithm instead if available. Unfortunately twofish is not yet available in the list of openssl ciphers.
*/
static void _twofish_cbc_encrypt(void* payload, size_t size)
{
}
static void _twofish_cbc_decrypt(void* payload, size_t size)
{
}
static void _aes_ctr_encrypt(void* payload, size_t size)
{

	AES_KEY* key = calloc(1, sizeof(AES_KEY));
	unsigned int state_num = 0;
	unsigned char state_ecount[AES_BLOCK_SIZE];

	memset(state_ecount, 0x0, AES_BLOCK_SIZE);

	// TODO : Variable Key Length
	AES_set_encrypt_key((const unsigned char*)(&(current_sa->esp_crypto_key[0])), 128, key);

	RAND_bytes((unsigned char*)(&(current_sa->iv)), 8);

	unsigned char iv[8];
	memcpy(iv, &(current_sa->iv), 8);
	
	AES_ctr128_encrypt((const unsigned char *)payload,
			(unsigned char *)payload,
			size, key, (unsigned char *)iv, state_ecount, &state_num);
/*
	ESP* esp = (ESP*)payload;
	printf("\nEncrypted : \n");
	int i;
	for(i = 1; i < 65; i++)
	{
		printf("%02x ", esp->body[i - 1]);
		if(i % 16 == 0)
				printf("\n");
	}
	printf("\n");
	*/
/*
	ESP* esp = (ESP*)payload;
		
	printf("\nEncrypted : \n");
	int i;
	for(i = 1; i < 65; i++)
		{
		printf("%02x ", esp->body[i - 1]);
		if(i % 16 == 0)
				printf("\n");
	}
	printf("\n");
*/
}
static void _aes_ctr_decrypt(void* payload, size_t size)
{
	AES_KEY* key = calloc(1, sizeof(AES_KEY));
	unsigned int state_num = 0;
	unsigned char state_ecount[AES_BLOCK_SIZE];

	memset(state_ecount, 0x0, AES_BLOCK_SIZE);
	
	ESP* esp = (ESP*)payload;
	
	unsigned char* iv = (unsigned char*)malloc(8);
	memcpy(iv, &(esp->iv), 8);
	// TODO : Variable Key Length
	AES_set_decrypt_key((const unsigned char*)(&(current_sa->esp_crypto_key[0])), 128, key);
	
	AES_ctr128_encrypt((const unsigned char *)esp->body, 
			(unsigned char *)esp->body, 
			size, key, iv, state_ecount, &state_num);
/*
	printf("\nDecrypted : \n");
	int i;
	for(i = 1; i < 65; i++)
	{
		printf("%02x ", esp->body[i - 1]);
		if(i % 16 == 0)
				printf("\n");
	}
	printf("\n");
	*/
/*
	printf("\nDecrypted : \n");
	int i;
	for(i = 1; i < 65; i++)
	{
		printf("%02x ", esp->body[i - 1]);
		if(i % 16 == 0)
				printf("\n");
	}
	printf("\n");
*/
}

// TODO : 16 Byte Alighment for Payload
// Key Length : 16, 24, 32 Bytes (Default : 16 Bytes)
static void _camellia_cbc_encrypt(void* payload, size_t size)
{
	CAMELLIA_KEY* key = calloc(1, sizeof(CAMELLIA_KEY));

	// TODO : Variable Key Length
	Camellia_set_key((const unsigned char*)(&(current_sa->esp_crypto_key[0])), 128, key);

	RAND_bytes((unsigned char*)(&(current_sa->iv)), 8);
	
	unsigned char iv[8];
	memcpy(iv, &(current_sa->iv), 8);

	Camellia_cbc_encrypt((const unsigned char *)payload,
			(unsigned char *)payload,
			size, key, (unsigned char *)iv, CAMELLIA_ENCRYPT);
/*
	ESP* esp = (ESP*)payload;
	
	printf("\nEncrypted : \n");
	int i;
	for(i = 1; i < 65; i++)
	{
		printf("%02x ", esp->body[i - 1]);
		if(i % 16 == 0)
				printf("\n");
	}
	printf("\n");
*/
}

static void _camellia_cbc_decrypt(void* payload, size_t size)
{
	CAMELLIA_KEY* key = calloc(1, sizeof(CAMELLIA_KEY));
	
	ESP* esp = (ESP*)payload;
	
	// TODO : Variable Key Length
	Camellia_set_key((const unsigned char*)(&(current_sa->esp_crypto_key[0])), 128, key);
	
	Camellia_cbc_encrypt((const unsigned char *)esp->body, 
			(unsigned char *)esp->body, 
			size, key, (unsigned char *)(&(esp->iv)), CAMELLIA_DECRYPT);
/*
	printf("\nDecrypted : \n");
	int i;
	for(i = 1; i < 65; i++)
	{
		printf("%02x ", esp->body[i - 1]);
		if(i % 16 == 0)
				printf("\n");
	}
	printf("\n");
*/
}

Cryptography cryptographys[] = 
{
	{.encrypt = _des_cbc_encrypt,	 	.decrypt = _des_cbc_decrypt},
	{.encrypt = _3des_cbc_encrypt, 		.decrypt = _3des_cbc_decrypt},
	{.encrypt = _blowfish_cbc_encrypt, 	.decrypt = _blowfish_cbc_decrypt},
	{.encrypt = _cast128_cbc_encrypt, 	.decrypt = _cast128_cbc_decrypt},
	{.encrypt = _des_deriv_encrypt, 	.decrypt = _des_deriv_decrypt},
	{.encrypt = _3des_deriv_encrypt, 	.decrypt = _3des_deriv_decrypt},
	{.encrypt = _rijndael_cbc_encrypt,  .decrypt = _rijndael_cbc_decrypt},
	{.encrypt = _twofish_cbc_encrypt, 	.decrypt = _twofish_cbc_decrypt},
	{.encrypt = _aes_ctr_encrypt,		.decrypt = _aes_ctr_decrypt},
	{.encrypt = _camellia_cbc_encrypt, 	.decrypt = _camellia_cbc_decrypt},
};

Cryptography* get_cryptography(int algorithm) 
{
		return &cryptographys[algorithm - 1];
}

