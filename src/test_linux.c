#include <openssl/des.h>
#include <stdio.h>
#include <thread.h>
#include <net/ni.h>
#include <net/packet.h>
#include <net/ether.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/udp.h>
#include <string.h>
#include <stdint.h>

uint64_t cpu_tsc()
{
        uint64_t time;
        uint32_t* p = (uint32_t*)&time;

        asm volatile("rdtsc" : "=a"(p[0]), "=d"(p[1]));

        return time;
}

int perf()
{
        DES_cblock key1, key2, key3, iv;
        DES_key_schedule ks1, ks2, ks3;

        char* payload = (char*)malloc(64);
        int i;
        uint64_t start, end;

       	memcpy(payload, "hello world hello world hello world\n", 64);
 
	// 1. Key & IV Extract
        memcpy(key1, "aeaeaeae", 8);
        memcpy(key2, "aeaeaeae", 8);
        memcpy(key3, "aeaeaeae", 8);

        memcpy(iv, "aeaeaeae", 8);

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
          
        start = cpu_tsc();

        for(i = 0; i < 1000000; i++)
        {       
                DES_ede3_cbc_encrypt((const unsigned char*)payload,
                                (unsigned char*)payload, 
                                64 , &ks1, &ks2, &ks3, &iv, DES_ENCRYPT);       
        }

        end = cpu_tsc();
	
        printf("encrpytion time : %ld\n", (end-start)/10000);
	
	start = cpu_tsc();

        for(i = 0; i < 1000000; i++)
        {
                DES_ede3_cbc_encrypt((const unsigned char*)payload,
                                (unsigned char*)payload,
                                64 , &ks1, &ks2, &ks3, &iv, DES_DECRYPT);
        }

        end = cpu_tsc();

        printf("decryption time : %ld\n", (end-start)/10000);

	return 0;
}


void ginit(int argc, char** argv) {
}

void init(int argc, char** argv) {
}

static uint32_t address = 0xc0a80a0a;	// 192.168.10.10
//static uint32_t address = 0xc0a8c80a;	// 192.168.200.10
//static uint32_t address = 0xc0a8640a;	// 192.168.100.10

void process(NetworkInterface* ni) {
	Packet* packet = ni_input(ni);
	if(!packet)
		return;
	if(arp_process(packet))
		return;
		
	Ether* ether = (Ether*)(packet->buffer + packet->start);
/*	
	if(endian16(ether->type) == ETHER_TYPE_ARP) {
		// ARP response
		ARP* arp = (ARP*)ether->payload;
		if(endian16(arp->operation) == 1 && endian32(arp->tpa) == address) {
			ether->dmac = ether->smac;
			ether->smac = endian48(ni->mac);
			arp->operation = endian16(2);
			arp->tha = arp->sha;
			arp->tpa = arp->spa;
			arp->sha = ether->smac;
			arp->spa = endian32(address);
			
			printf("- Ethernet Header -\n");
			printf("Dst Mac : %012lx Src Mac : %012lx\n Ether Type : %04hx\n", 
			endian48(ether->dmac), endian48(ether->smac), ether->type);

			ni_output(ni, packet);
			packet = NULL;
		}
	}*/
	if(endian16(ether->type) == ETHER_TYPE_IPv4) {
		IP* ip = (IP*)ether->payload;
		
		if(ip->protocol == IP_PROTOCOL_ICMP && endian32(ip->destination) == address){
			// Echo reply
			ICMP* icmp = (ICMP*)ip->body;
		
			// Performance check
//			perf();
	
			icmp->type = 0;
			icmp->checksum = 0;
			icmp->checksum = endian16(checksum(icmp, packet->end - packet->start - ETHER_LEN - IP_LEN));
			
			ip->destination = ip->source;
			ip->source = endian32(address);
			ip->ttl = endian8(64);
			ip->checksum = 0;
			ip->checksum = endian16(checksum(ip, ip->ihl * 4));
			
			ether->dmac = ether->smac;
			ether->smac = endian48(ni->mac);
			
			ni_output(ni, packet);
			packet = NULL;
		}
			/*
		} else if(ip->protocol == IP_PROTOCOL_TCP) {
			TCP* tcp = (TCP*)ip->body;
			
			printf("source=%u, destination=%u, sequence=%u, acknowledgement=%u\n", 
				endian16(tcp->source), endian16(tcp->destination), endian32(tcp->sequence), endian32(tcp->acknowledgement));
			printf("offset=%d, ns=%d, cwr=%d, ece=%d, urg=%d, ack=%d, psh=%d, rst=%d, syn=%d, fin=%d\n", 
				tcp->offset, tcp->ns, tcp->cwr, tcp->ece, tcp->urg, tcp->ack, tcp->psh, tcp->rst, tcp->syn, tcp->fin);
			printf("window=%d, checksum=%x, urgent=%d\n", endian16(tcp->window), endian16(tcp->checksum), endian16(tcp->urgent));
			*/
	}
	
	if(packet)
		ni_free(packet);
}

void destroy() {
}

void gdestroy() {
}

int main(int argc, char** argv) {
	//printf("Thread %d bootting\n", thread_id());
	if(thread_id() == 0) {
		ginit(argc, argv);
	}
	
	thread_barrior();
	
	init(argc, argv);
	
	thread_barrior();
	
	printf("PacketNgin APP Start\n");	

	perf();

	perf();

	perf();

	/*
	uint32_t i = 0;
	while(1) {
		uint32_t count = ni_count();
		if(count > 0) {
			i = (i + 1) % count;
			
			NetworkInterface* ni = ni_get(i);
			if(ni_has_input(ni)) {
				process(ni);
			}
		}
	}
	*/	
	thread_barrior();
	
	destroy();
	
	thread_barrior();
	
	if(thread_id() == 0) {
		gdestroy(argc, argv);
	}

	while(1);
	
	return 0;
}
