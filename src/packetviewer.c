#include "packetviewer.h"

void send_new_udp_packet(NetworkInterface* ni, Ether* ether, int type)
{
	IP* ip = (IP*)ether->payload;
	
	// Packet = Ether (14) + IP (20) + UDP (8) + Payload ( Ether + ip->length )
	int packet_len = 16 + 20 + 8 + 14 + endian16(ip->length);
	if(packet_len > 1500)
			printf("Packet length: %d\n", packet_len);
	
	Packet* packet = (Packet*)ni_alloc(ni, packet_len);
	
	if(packet == NULL)
	{
		printf("Packet NULL\n");
		return ;
	}
	
	packet->end = packet->start + packet_len;

	// 1. Ethernet Header
	Ether* dup_ether = (Ether*)(packet->buffer + packet->start);
	dup_ether->dmac = endian48(arp_get_mac(ni, HOST_IP_ADDRESS));
	//dup_ether->dmac = ether->smac
	dup_ether->smac = endian48(ni->mac);
	dup_ether->type = ether->type;

	// 2. IP Header
	IP* dup_ip = (IP*)dup_ether->payload;

	dup_ip->ihl = 5;
	dup_ip->version = 4;
	dup_ip->ecn = 0;
	dup_ip->dscp = 0;
	dup_ip->length = endian16(packet_len - 14 /* Ether */);
	dup_ip->id = endian16(0x8000);
	dup_ip->flags_offset = 0x40;
	dup_ip->ttl = 64;
	dup_ip->protocol = IP_PROTOCOL_UDP;
	dup_ip->source = endian32(GW_IP_ADDRESS); 
	dup_ip->destination = endian32(HOST_IP_ADDRESS);
	dup_ip->checksum = 0;
	dup_ip->checksum = endian16(checksum(dup_ip, dup_ip->ihl * 4));

	// 3. UDP Header
	UDP* dup_udp = (UDP*)dup_ip->body;
	
	
	//dup_udp->destination = endian16(50000);
	if(type == INBOUND)
		dup_udp->destination = endian16(UDP_IN_PORT_NUM);
	else if(type == OUTBOUND)
		dup_udp->destination = endian16(UDP_OUT_PORT_NUM);
	
	dup_udp->length = endian16(packet_len - 16 /* Ether */ - 20 /* IP */);
	dup_udp->checksum = 0;
	
	memcpy(dup_udp->body, ether, packet_len - 16 /* Ether */ - 20 /* IP */ - 8 /* UDP */);

#ifdef _DEBUG_
	printf("- NEW UDP PACKET -\n");
	printf("Dst Mac : %012lx Src Mac : %012lx\n Ether Type : %04hx\n", 
			endian48(dup_ether->dmac), endian48(dup_ether->smac), dup_ether->type);
	printf("- IP Header - \n");
	for(int i = 1; i < 51; i++)
	{
		printf("%02x ", dup_ether->payload[i - 1]);
		if(i % 16 == 0)
			printf("\n");
	}
#endif 	
	ni_output(ni, packet);
}
