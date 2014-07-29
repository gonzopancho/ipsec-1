#include "IPSec.h"

#ifdef _INPUT_
#define IN_PACKET_LEN 	136 //108(Transport)
#define OUT_PACKET_LEN 	84
#define PRINT 			printf	

#ifdef _TP_
   SP sp = 
   {
   .source 	     = 0xc0a864c8, //0xc0a80101, 192.168.100.200
   .destination  = 0xc0a8640a, //0xc0a801fe, 192.168.100.10
   .action       = IPSEC,
   .protocol     = IP_PROTOCOL_ESP,
   .mode		 = TRANSPORT,
   .direction    = IN
   };

   SP sp2 = 
   {
   .source 	 	 = 0xc0a8640a,
   .destination  = 0xc0a864c8,
   .action	 	 = IPSEC,
   .protocol	 = IP_PROTOCOL_ESP,
   .mode 		 = TRANSPORT,
   .direction	 = OUT
   };

   ESP_algo algo = 
   {
   .algorithm   = TDES_CBC,
   .esp_key[0]  = 0xaeaeaeaeaeaeaeae,
   .esp_key[1]  = 0xaeaeaeaeaeaeaeae,
   .esp_key[2]  = 0xaeaeaeaeaeaeaeae,
   };

   SA sa = 
   {
   .SPI			 = 0x201,
   .protocol   	 = IP_PROTOCOL_ESP,
   .source   	 = 0xc0a864c8, //0xc0a80101, 192.168.100.200
   .destination	 = 0xc0a8640a, //0xc0a801fe, 192.168.100.10
   .seq_counter	 = 0,
   .mode 		 = TRANSPORT,
   .esp_algo 	 = &algo
   };

   SA sa2 = 
   {
   .SPI	    	 = 0x301,
   .protocol	 = IP_PROTOCOL_ESP,
   .source 		 = 0xc0a8640a,
   .destination  = 0xc0a864c8,
   .seq_counter	 = 0,
   .mode 		 = TRANSPORT,
   .esp_algo   	 = &algo
   };
#endif
// Tunnel Setting
#ifndef _TP_
SP sp = 
{
	.source 		 = 0xac100100,
	.destination	 = 0xac100200,
	.t_source        = 0xc0a80164,
	.t_destination 	 = 0xc0a80264,
	.action     	 = IPSEC,
	.protocol   	 = IP_PROTOCOL_ESP,
	.mode			 = TUNNEL,
	.direction  	 = OUT
};

SP sp2 = 
{
	.source 	 	= 0xac100200,//200
	.destination 	= 0xac100100,//100
	.t_source       = 0xc0a80264,//264
	.t_destination 	= 0xc0a80164,//164
	.action	 		= IPSEC,
	.protocol		= IP_PROTOCOL_ESP,
	.mode 			= TUNNEL,
	.direction		= IN
};

ESP_algo algo = 
{
	.algorithm  = TDES_CBC,
	.esp_key[0]	= 0x7aeaca3f87d060a1,
	.esp_key[1] = 0x2f4a4487d5a5c335,
	.esp_key[2] = 0x5920fae69a96c831,
//	.key1 		= 0xaeaeaeaeaeaeaeae,
//	.key2 		= 0xaeaeaeaeaeaeaeae,
//	.key3 		= 0xaeaeaeaeaeaeaeae,
	.ah_key[0] 	= 0xc0291ff014dccdd0,
	.ah_key[1]  = 0x3874d9e8e4cdf3e6
};

ESP_algo algo2 = 
{
	.algorithm  = TDES_CBC,
	.esp_key[0]	= 0xf6ddb555acfd9d77,
	.esp_key[1]	= 0xb03ea3843f265325,
	.esp_key[2] = 0x5afe8eb5573965df,
//	.key1 		= 0xaeaeaeaeaeaeaeae,
//	.key2 		= 0xaeaeaeaeaeaeaeae,
//	.key3 		= 0xaeaeaeaeaeaeaeae,
	.ah_key[0]	= 0x96358c90783bbfa3,
	.ah_key[1]  = 0xd7b196ceabe0536b
};

SA sa = 
{
	.SPI		 = 0x201,
	.protocol    = IP_PROTOCOL_ESP,
	.mode 		 = TUNNEL,
	.source   	 = 0xc0a80164,
	.destination = 0xc0a80264,
	.seq_counter = 0,
	.esp_algo 	 = &algo
};

SA sa2 = 
{
	.SPI	     = 0x301,
	.protocol	 = IP_PROTOCOL_ESP,
	.mode	     = TUNNEL,
	.source 	 = 0xc0a80264,
	.destination = 0xc0a80164,
	.seq_counter = 0,
	.esp_algo    = &algo2
};
#endif
SPD spd;
SAD sad;

SA* current_sa;
SP* current_sp;

#endif

uint64_t entire_t;
uint64_t spd_lookup_out_t;
uint64_t spd_lookup_in_t;

uint64_t sad_lookup_out_t;
uint64_t sad_lookup_in_t;
uint64_t encryption_t;
uint64_t headermake_t;
uint64_t headerdelete_t;

uint64_t icvcalc_t;
uint64_t icvcheck_t;
uint64_t decryption_t;

uint64_t hmac_t;

inline uint64_t cpu_tsc() {
	uint64_t time;
	uint32_t* p = (uint32_t*)&time;
	asm volatile("rdtsc" : "=a"(p[0]), "=d"(p[1]));

	return time;
}

int IPSec_Module(void)
{
	// intialization
	SP_node* sp_header_node = (SP_node*)malloc(sizeof(SP_node));
	SA_node* sa_header_node = (SA_node*)malloc(sizeof(SA_node));

	SP_node* sp_node1 = (SP_node*)malloc(sizeof(SP_node));
	SP_node* sp_node2 = (SP_node*)malloc(sizeof(SP_node));

	SA_node* sa_node1 = (SA_node*)malloc(sizeof(SA_node));
	SA_node* sa_node2 = (SA_node*)malloc(sizeof(SA_node));

	spd.sp_list = sp_header_node;
	sad.sa_list = sa_header_node;

	sp_node1->sp = &sp;
	sp_node2->sp = &sp2;
	sa_node1->sa = &sa;
	sa_node2->sa = &sa2;

	INIT_LIST_HEAD(&((spd.sp_list)->list));
	INIT_LIST_HEAD(&((sad.sa_list)->list));

	list_add(&(sp_node1->list), &((spd.sp_list)->list));
	list_add(&(sp_node2->list), &((spd.sp_list)->list));
	list_add(&(sa_node1->list), &((sad.sa_list)->list));
	list_add(&(sa_node2->list), &((sad.sa_list)->list));

	
	#ifdef _TP_
	printf(" - TRANSPORT MODE - ");
	#endif
///*
//	IP* ip;
//// Packet In & Output
//	// Transport Mode
//	#ifdef _TP_
//	printf(" - TRANSPORT MODE - ");
//		unsigned char in_ip[] = 
//		{
//		0x45, 0x00, 0x00, 0x6c, 0x00, 0x00, 0x40, 0x00,
//		0x40, 0x32, 0xb6, 0x10, 0xc0, 0xa8, 0x01, 0x01, 
//		0xc0, 0xa8, 0x01, 0xfe, 0x00, 0x00, 0x02, 0x01,
//		0x00, 0x00, 0x00, 0x01, 0xeb, 0x2e, 0xfb, 0x3c, 
//		0x28, 0x18, 0x70, 0xc3, 0xe1, 0xff, 0x13, 0xa4, 
//		0xf7, 0x37, 0x56, 0x34, 0x00, 0x63, 0x56, 0x9b, 
//		0xd6, 0x10, 0xfc, 0x41, 0xe0, 0xc7, 0xe9, 0x55, 
//		0x4d, 0xd3, 0xf9, 0xe3, 0xfa, 0xf1, 0x56, 0xb6, 
//		0x3a, 0x19, 0x80, 0x06, 0x39, 0x26,	0xa3, 0xbe, 
//		0x4d, 0xff, 0xbf, 0x9d, 0x89, 0xab, 0x36, 0xbe, 
//		0x8f, 0x1b, 0xc1, 0xbf, 0x1e, 0xf2, 0x6d, 0xac, 
//		0xb1, 0x4e, 0xba, 0x81, 0x07, 0x6b, 0xf0, 0x2a, 
//		0xa4, 0x66, 0x42, 0xd0,	0x4c, 0xc2, 0x89, 0xfc, 
//		0x67, 0xc8, 0x76, 0xd6
//		};
//
//		unsigned char out_ip[] = 
//		{
//		0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
//		0x40, 0x01, 0xb6, 0x59, 0xc0, 0xa8, 0x01, 0x01,
//		0xc0, 0xa8, 0x01, 0xfe, 0x08, 0x00, 0x26, 0x26,
//		0x11, 0xaf, 0x00, 0x01, 0x0a, 0xff, 0x3b, 0x53,
//		0x00, 0x00, 0x00, 0x00, 0xb4, 0x04, 0x07, 0x00,
//		0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13,
//		0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
//		0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 
//		0x24, 0x25,	0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
//		0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
//		0x34, 0x35, 0x36, 0x37
//		};
//	#endif 	
//	// Tunnel Mode
//	#ifndef _TP_
//	printf(" - TUNNEL MODE - ");
//	unsigned char out_ip[] = 
//	{
//		0x45, 0x00,	0x00, 0x54, 0x00, 0x00, 0x40, 0x00, 
//		0x40, 0x01,	0xdf, 0x88, 0xac, 0x10, 0x01, 0x00, 
//		0xac, 0x10,	0x02, 0x00, 0x08, 0x00, 0x05, 0x59, 
//		0x13, 0x6a,	0x00, 0x01, 0xb0, 0xe7, 0x70, 0x53, 
//		0x00, 0x00,	0x00, 0x00, 0xf7, 0x2d, 0x08, 0x00, 
//		0x00, 0x00,	0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 
//		0x14, 0x15,	0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 
//		0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 
//		0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 
//		0x2c, 0x2d,	0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 
//		0x34, 0x35, 0x36, 0x37
//	};
//
//	unsigned char in_ip[] = 
//	{
//		0x45, 0x00, 0x00, 0x88, 0xf4, 0x94, 0x00, 0x00,
//		0x40, 0x32, 0x00, 0x97, 0xc0, 0xa8, 0x02, 0x64,
//		0xc0, 0xa8, 0x01, 0x64, 0x00, 0x00, 0x03, 0x01,
//		0x00, 0x00, 0x00, 0x05, 0xad, 0xa5, 0x55, 0xa4,
//		0xd6, 0x61, 0xe2, 0x96, 0x73, 0x5c, 0xe0, 0x66,
//		0x06, 0x75, 0x2e, 0x5b, 0x33, 0xbe, 0x7d, 0xf2,
//		0x19, 0x24, 0xd8, 0x4a, 0x1e, 0xd0, 0x21, 0xbd,
//		0x16, 0x5d, 0x48, 0x03, 0xc1, 0xe4, 0xe1, 0x0e,
//		0xb5, 0xf1, 0xc4, 0x4a, 0xa6, 0x3d, 0x6a, 0xef,
//		0x6b, 0xdf, 0x0e, 0x46, 0x01, 0x22, 0x7d, 0xdd,
//		0x37, 0x66, 0x4a, 0xd8, 0x94, 0xe1, 0x58, 0x40,
//		0x1e, 0xe0, 0x9d, 0x0f, 0x9e, 0xeb, 0x2e, 0xf6,
//		0x62, 0x31, 0xf4, 0xee, 0x4e, 0x7d, 0xfa, 0x85,
//		0xdf, 0x23, 0x01, 0x2e, 0x1b, 0x27, 0x56, 0xb3,
//		0x4a, 0x73, 0x89, 0x7c, 0x4d, 0x0b, 0xa7, 0xef,
//		0xfe, 0x8a, 0x3f, 0x84, 0xc3, 0xf9, 0xb1, 0x37,
//		0x86, 0xe9, 0x9e, 0x9c, 0x6d, 0xe4, 0x4c, 0xbe
//	};
//	#endif
//	
//  ip = (IP*)malloc(OUT_PACKET_LEN + 20 + 24 + 12 + 100); 
//	// 20 : Inner IP, 24 : ESP Header + Trailer, 12 : ICV 
//   memset(ip, 0x0, OUT_PACKET_LEN + 20 + 24 + 12 + 100);
//    memcpy(ip, out_ip, OUT_PACKET_LEN);
///*		
//	ip = (IP*)malloc(IN_PACKET_LEN);
//	memset(ip, 0x0, IN_PACKET_LEN);
//	memcpy(ip, in_ip, IN_PACKET_LEN);
//*/
//	// Print Original Packet
///*	PRINT("Original Packet : \n");
//	for(i = 1; i < 1 + OUT_PACKET_LEN; i++)
//	{
//		PRINT("%02x ", out_ip[i - 1]); // Packet - IP Header 
//		if( i % 16 == 0 )
//			PRINT("\n");
//	}
//	PRINT("\n");
//*/
//	//	for(i = 0; i < 100000;i++)
////	{
//	uint64_t entire_s = cpu_tsc() ;
//	if(outbound(ip) < 0);
////		continue;	//PRINT("OUTBOUND PROCESSING FAILED : DISCARD PACKET\n");
//
//	if(inbound(ip) < 0);
////		continue;   //PRINT("INBOUND PROCESSING FAILED : DISCARD PACKET\n");
////	}
//	uint64_t entire_e = cpu_tsc();
//	//free(ip);
//	entire_t =(entire_e - entire_s);
//
////	printf("total clock : %f\n", (float)entire_t);	
////	printf("spd_lookup_in : %f\n", ((float)sad_lookup_in_t/entire_t));
////	printf("sad_lookup_out : %f\n", ((float)sad_lookup_out_t/entire_t));
////	printf("spd_lookup_in : %f\n", ((float)spd_lookup_in_t/entire_t));
////	printf("spd_lookup_out : %f\n", ((float)spd_lookup_out_t/entire_t));
////	printf("encryption : %f\n", ((float)encryption_t/entire_t));
////	printf("decryption : %f\n", ((float)decryption_t/entire_t));
////	printf("headermake : %f\n", ((float)headermake_t/entire_t));
////	printf("headerdelete : %f\n", ((float)headerdelete_t/entire_t));
////	printf("icvcalc : %f\n", ((float)icvcalc_t/entire_t));
////	printf("icvcheck : %f\n", ((float)icvcheck_t/entire_t));
////
////	printf("hamc : %f\n", ((float)hmac_t/icvcalc_t));

	return 0;
}

int outbound(IP* ip)
{
	uint64_t outbound_s = cpu_tsc();

	ESP* esp = NULL;
	int i = 0, len = 0, pad_len = 0;

	current_sa = 0;
	current_sp = 0;

	PRINT("\n\t == OUTBOUND PROCESSING ==\n");
	// 1. SPD lookup
	uint64_t spd_lookup_out_s = cpu_tsc();
	current_sp = SPD_lookup_out(ip);
	uint64_t spd_lookup_out_e = cpu_tsc();
	spd_lookup_out_t = (spd_lookup_out_e - spd_lookup_out_s);
	
	if(current_sp == NULL)
	{
		PRINT("STEP 1. SPD lookup : Bypass ip (No SP)\n");
		// Bypass routine
		return -1;
	}

	PRINT("STEP 1. SPD lookup : hit\n");

	// 2. SAD lookup
	uint64_t sad_lookup_out_s = cpu_tsc();
	current_sa = SAD_lookup_out(ip);
	uint64_t sad_lookup_out_e = cpu_tsc();
	sad_lookup_out_t = (sad_lookup_out_e - sad_lookup_out_s);

	if(current_sa == NULL)
	{
		PRINT("STEP 2. SAD lookup : Discard ip (No SA)\n");
		return -1;
	}
	PRINT("STEP 2. SAD lookup : hit \n");

	uint64_t encryption_s = cpu_tsc();
	// Branch by protocol
	switch(current_sp->protocol)
	{
		case IP_PROTOCOL_ESP :
			switch(current_sp->mode)
			{
				case TRANSPORT :
					// Need to be implemented in esp_outbound();
					// Branch by algorithm
					switch(current_sa->esp_algo->algorithm)
					{
						// 3. Encryption
						case TDES_CBC :
							if(des3_cbc_encrypt(ip, current_sa) >= 0)
							{
								PRINT("STEP 3. Encryption : Encryption Completed\n");
							}
							else
							{
								PRINT("STEP3. Encryption : Discard ip (Encryption failed)\n");
								return 0;
							}
							// Other algorithm here
						default : break;
					}
					
					// 4. ESP Header & Trailer addition
					// IP Header Making
					ip->protocol = IP_PROTOCOL_ESP;
					len = endian16(ip->length) - (ip->ihl * 4); // Payload length
					pad_len = 8 - (len + 2) % 8; // Padding length
					ip->length = endian16(endian16(ip->length) + 16 + 2 + pad_len);// + 12); // ESP Header + ESP Trailer + Padding length + (ICV Key)
					
					// ESP Header Making
				//	esp = (ESP*)malloc(ip->length);
					memmove(ip->body + sizeof(ESP), ip->body, endian16(ip->length));
					esp = (ESP*)ip->body;
					esp->SPI = endian32(current_sa->SPI);

					// 5. Seq# Validation : overflow Check here
					esp->seq_num = endian32(++current_sa->seq_counter);

					memcpy(&(esp->IV), &(current_sa->esp_algo->iv), 8);
					
					// Payload copy
					//len += pad_len + 2; // Payload + Padding + ESP Trailer
					//memcpy(esp->body, ip->body, len);

					// Header Overwrite
			   //	memcpy(ip->body, esp, len + 16); 
			   		
			  		 // 6. ICV Calculation
					/*
					if(hmac_md5_icv_calc(ip, current_sa) >= 0)
					{
						PRINT("STEP 4. Authentication : ICV Calculation Completed\n");
					}
					else
					{
						PRINT("STEP 4. Authentication : Discard ip (Authentication failed)\n");
						return 0;
					}*/
					// Only when ICV turn on : ECN = 0
					break;
				case TUNNEL :
					// Inner IP Making
					ip->ttl--;
					ip->checksum = 0;
					ip->checksum = endian16(checksum(ip, ip->ihl * 4));

					memmove(ip->body, ip, endian16(ip->length));
					// !! Need more processing for inner IP (Hop limit --) !!
					switch(current_sa->esp_algo->algorithm)
					{
						// 3. Encryption
						case TDES_CBC :
							if(des3_cbc_encrypt(ip, current_sa) >= 0)
							{
								PRINT("STEP 3. Encryption : Encryption Completed\n");
							}
							else
							{
								PRINT("STEP3. Encryption : Discard ip (Encryption failed)\n");
								return 0;
							}
							break;
							// Other algorithm here
						default : break;
					}
					uint64_t encryption_e = cpu_tsc();
					encryption_t = (encryption_e - encryption_s);

					uint64_t headermake_s = cpu_tsc();
					// 4. ESP Header & Trailer addition

					// Outer IP Header Making 
					ip->protocol = IP_PROTOCOL_ESP;
					len = endian16(ip->length); // Payload length
					pad_len = 8 - (len + 2) % 8; // Padding length
					
					ip->length = endian16(endian16(ip->length) + 16 + 2 + pad_len + 20 + 12); 
					// ESP Header + ESP Trailer + Padding length + Inner IP + ICV Key
					
					// !! More filed to be impelement !!
					// flags, fragment offset, checksum ...
					
					// ESP Header Making
					memmove(ip->body + sizeof(ESP), ip->body, endian16(ip->length));
					esp = (ESP*)ip->body;
				//	esp = (ESP*)malloc(endian16(ip->length));
					esp->SPI = endian32(current_sa->SPI);

					// !! Need to be impelement : Seq# overflow Check !! 

					esp->seq_num = endian32(++current_sa->seq_counter);

					memcpy(&(esp->IV), &(current_sa->esp_algo->iv), 8);
					
					// Payload copy
					len += pad_len + 2; // Payload + Padding + ESP Trailer
					
			//		memcpy(esp->body, ip->body, len);

					// Header Overwrite
			//		memcpy(ip->body, esp, len + 16); 
					uint64_t headermake_e = cpu_tsc();
					headermake_t = (headermake_e - headermake_s);

					// 5. ICV Calculation 
					uint64_t icvcalc_s = cpu_tsc();
					if(hmac_md5_icv_calc(ip, current_sa) >= 0)
					{
						PRINT("STEP 4. Authentication : ICV Calculation Completed\n");
					}
					else
					{
						PRINT("STEP 4. Authentication : Discard ip (Authentication failed)\n");
						return 0;
					}
					uint64_t icvcalc_e = cpu_tsc();
					icvcalc_t = (icvcalc_e - icvcalc_s);
					// Only when ICV turn on : ECN = 0
					break;
				default : break;
			}
		case IP_PROTOCOL_AH:
		default : break;
	}

	// Print protected IP 
	PRINT("Encrypted Packet : \n");
	
	int innerIP_len = 0;
#ifndef _TP_
	innerIP_len = 20;
#endif 

	Ether* ether = (Ether*)malloc(OUT_PACKET_LEN + 100);
	memmove(ether->payload, ip, OUT_PACKET_LEN + (16 + pad_len + 2) + (innerIP_len) + 12); 
	
	for(i = 1; i < 1 + OUT_PACKET_LEN + (16 + pad_len + 2) + (innerIP_len) + 12; i++) 
		// (ESP) + (Inner IP)(optional) + (ICV)
	{
		PRINT("%02x ", ether->payload[i - 1]); // Packet - IP Header 
		if( i % 16 == 0 )
			PRINT("\n");
	}
	PRINT("\n");
	uint64_t outbound_e = cpu_tsc();

	return 0;
}

int inbound(IP* ip)
{
	ESP* esp;
	int i = 0, len = 0, pad_len = 0;

	current_sa = 0;
	current_sp = 0;

	PRINT("\n\t == INBOUND PROCESSING ==\n");
	// 1. SAD lookup
	uint64_t sad_lookup_in_s = cpu_tsc();
	current_sa = SAD_lookup_in(ip);
	uint64_t sad_lookup_in_e = cpu_tsc();
	sad_lookup_in_t = (sad_lookup_in_e - sad_lookup_in_s);

	if(current_sa == NULL)
	{
		PRINT("STEP 1. SAD lookup : Discard ip (No SA)\n");
		return -1;
	}
	PRINT("STEP 1. SAD lookup : hit \n");
	
	switch(current_sa->mode)
	{
		case TRANSPORT :
			// 2. SPD lookup
			current_sp = SPD_lookup_in(ip);

			if(current_sp == NULL)
			{
				PRINT("STEP 2. SPD lookup : Discard ip (No SP)\n");
				return -1;
			}
			PRINT("STEP 2. SPD lookup : hit \n");

			// branch by protocol
			switch(current_sp->protocol)
			{
				case IP_PROTOCOL_ESP :
					// ESP_inbound();
					// Branch by algorithm
					switch(current_sa->esp_algo->algorithm)
					{
						// 3. Seq# Validation
						case TDES_CBC :
							esp = (ESP*)ip->body;

							if(seq_validate(current_sa, esp->seq_num) >= 0)	
							{
								PRINT("STEP 3. Seq# Validation : valid\n");
							}
							else
							{
								PRINT("STEP 3. Seq# Validation : Discard ip \n");
								return -1;
							}	

							// 4. ICV Validation
							
//							if(hmac_md5_icv_check(ip, current_sa) >= 0)
//							{
//								PRINT("STEP 4. Authentication : ICV Check Completed\n");
//							}
//							else
//							{
//								PRINT("STEP 4. Authentication : Discard ip (Authentication failed)\n");
//								return 0;
//							}
//							// Only when ICV is turned on : ECN = 0
		
							// 5. Decrypt
							if(des3_cbc_decrypt(ip, current_sa) >= 0)
							{
								PRINT("STEP 4. Decryption : Decryption Completed\n");
							}
							else
							{
								PRINT("STEP 4. Decryption : Discard ip (Decryption failed)\n");
							}
							// 6. ESP Header & Trailer deletion
							len = endian16(ip->length) - (ip->ihl * 4) - 16;// - 12; // Payload length : Entire IP - IP Header - ESP Header - (ICV Key)
							pad_len = 8 - (len + 2) % 8; // Padding length
					
							ip->length = endian16(endian16(ip->length) - 16 - 2 - pad_len); 
							// Protocol Change  
							ip->protocol = esp->body[len-1];
							// Header Overwrite	
							memmove(ip->body, esp->body, len);
							// ? Trailer deletion 
							
							// Other algorithm hered

							break;
						case IP_PROTOCOL_AH: break;
						default : break;
					}
			}
			break;
	
		case TUNNEL :
			// 2. Seq# Validation
			esp = (ESP*)ip->body;

			if(seq_validate(current_sa, esp->seq_num) >= 0)	
			{
				PRINT("STEP 2. Seq# Validation : valid\n");
			}
			else
			{
				PRINT("STEP 2. Seq# Validation : Discard ip \n");
				return -1;
			}	
			
			// 3. ICV Validation
			uint64_t icvcheck_s = cpu_tsc();

			if(hmac_md5_icv_check(ip, current_sa) >= 0)
			{
				PRINT("STEP 4. Authentication : ICV Check Completed\n");
			}
			else
			{
				PRINT("STEP 4. Authentication : Discard ip (Authentication failed)\n");
				return 0;
			}
			// Only when ICV is turned on : ECN = 0
			uint64_t icvcheck_e = cpu_tsc();
			icvcheck_t = (icvcheck_e - icvcheck_s);

			uint64_t decryption_s = cpu_tsc();
			// branch by protocol
			switch(current_sa->protocol)
			{
				case IP_PROTOCOL_ESP :
					// ESP_inbound();
					// Branch by algorithm
					switch(current_sa->esp_algo->algorithm)
					{
						case TDES_CBC :
							// 4. Decrypt
							if(des3_cbc_decrypt(ip, current_sa) >= 0)
							{
								PRINT("STEP 3. Decryption : Decryption Completed\n");
							}
							else
							{
								PRINT("STEP 3. Decryption : Discard ip (Decryption failed)\n");
							}
							uint64_t decryption_e = cpu_tsc();
							decryption_t = (decryption_e - decryption_s);

							// 6. Outer IP & ESP Header & Trailer deletion
							uint64_t headerdelete_s = cpu_tsc();
							len = endian16(ip->length) - (ip->ihl * 4) - 16  - 12; // Payload length : Entire IP - IP Header - ESP Header - ICV Key 
							pad_len = 8 - (len + 2) % 8; // Padding length
							
							ip->length = endian16(endian16(ip->length) - 16 - 2 - pad_len - 20 - 12); 
							
							// Protocol Change  
							int protocol_num = esp->body[len-1];
														
							// Header Overwrite
							memmove(ip, esp->body, len);  
	
							ip->protocol = protocol_num;
							// ? Trailer deletion 
							uint64_t headerdelete_e = cpu_tsc();
							headerdelete_t = (headerdelete_e - headerdelete_s);
							// 7. SPD lookup
							uint64_t spd_lookup_in_s = cpu_tsc();
							current_sp = SPD_lookup_in(ip);

							if(current_sp == NULL)
							{
								PRINT("STEP 4. SPD lookup : Discard ip (No SP)\n");
								return -1;
							}
							PRINT("STEP 4. SPD lookup : hit \n");
							uint64_t spd_lookup_in_e = cpu_tsc();
							spd_lookup_in_t = (spd_lookup_in_e - spd_lookup_in_s);
							// Other algorithm here
							break;
						case IP_PROTOCOL_AH: break;
						default : break;
					}
			}

			break;
	}

	Ether* ether1 = (Ether*)malloc(OUT_PACKET_LEN + 100);
	memmove(ether1->payload, ip, OUT_PACKET_LEN) ; 
	
	// Print protected Packet 	
	PRINT("Decrypted Packet : \n");
	for(i = 1; i < 1 + OUT_PACKET_LEN ; i++)
	{
		PRINT("%02x ", ether1->payload[i - 1]); // Packet - IP Header 
		if( i % 16 == 0 )
			PRINT("\n");
	}
	PRINT("\n");
	return 0;

}