#ifndef __PACKETVIEWER_H__
#define __PACKETVIEWER_H__

#include <stdio.h>
#include <string.h>
#include <net/checksum.h>
#include <net/arp.h>
#include <net/packet.h>
#include <net/udp.h>
#include <net/ni.h>
#include <net/ether.h>
#include <net/ip.h>

#define UDP_IN_PORT_NUM	 1111
#define UDP_OUT_PORT_NUM 2222
#define HOST_IP_ADDRESS  0xc0a80a63 // 192.168.100.99 
// 192.168.10.52(Windows)
#define GW_IP_ADDRESS 	 0xc0a80a33 // 192.168.10.51
#define INBOUND			 0x01
#define OUTBOUND		 0x02

void send_new_udp_packet(NetworkInterface* ni, Ether* ether, int type);

#endif /*__PACKETVIEWER_H__ */
