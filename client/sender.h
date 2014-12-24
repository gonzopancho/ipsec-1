#ifndef __SENDER_H__
#define __SENDER_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SETKEY_ADD			0x01
#define SETKEY_GET			0x02
#define SETKEY_DELETE		0x03
#define SETKEY_DELETEALL	0x04
#define SETKEY_FLUSH		0x05
#define SETKEY_DUMP			0x06

#define SETKEY_SPDADD		0x11
#define SETKEY_SPDUPDATE	0x12
#define SETKEY_SPDDELETE	0x13
#define SETKEY_SPDFLUSH		0x14	
#define SETKEY_SPDDUMP		0x15

#ifdef _GW1_
#define IPSEC_ADDR		    "192.168.10.153"
#define IPSEC_PORT	 		1234	
#endif
#ifdef _GW2_
#define IPSEC_ADDR			"192.168.100.10"
#define IPSEC_PORT	 		4321
#endif

typedef struct
{
	uint8_t name;
	uint32_t src_ip;
	uint32_t dst_ip;
	uint32_t src_mask;
	uint32_t dst_mask;
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t spi;
	uint8_t extension;
	uint8_t crypto_algorithm;
	uint8_t auth_algorithm;
	uint64_t crypto_key[3];
	uint64_t auth_key[8];
	uint8_t upperspec;
	uint8_t direction;
	uint8_t action;
	uint8_t protocol;
	uint8_t extensions;
	uint8_t mode;
	uint32_t t_src_ip;
	uint32_t t_dst_ip;
	uint8_t level;
} __attribute__ ((packed)) Parameter;

Parameter parameter;

int setkey_send();

#endif /* __SENDER_H__ */
