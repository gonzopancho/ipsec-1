#include "ipsec.h"


void init_list()
{
	SP* sp_header_node = (SP*)malloc(sizeof(SP));
	SA* sa_header_node = (SA*)malloc(sizeof(SA));

	spd.sp_list = sp_header_node;
	sad.sa_list = sa_header_node;
	
	INIT_LIST_HEAD(&((spd.sp_list)->list));
	INIT_LIST_HEAD(&((sad.sa_list)->list));

	spd.size = 0;
	sad.size = 0;
}

int decrypt(IP* packet)
{
	int size; 
	current_sa = NULL;
	current_sp = NULL;
	ESP* esp;
	IP* ip;

#ifdef _DEBUG_
	printf("Decrypt Processing : \n");
#endif	

	// 1. SAD Lookup
	if((current_sa = getSA(packet)) == NULL)
	{
#ifdef _DEBUG_
		printf(" 1. SAD Lookup : Discard packet \n");
#endif	
		return -1;
	}
	
	current_sa->crypto = get_cryptography(current_sa->esp_crypto_algorithm);
	current_sa->auth = get_authentication(current_sa->esp_auth_algorithm);

	
	// 2. Seq# Validation
	esp = (ESP*)packet->body;

	if(checkWindow(current_sa->window, esp->seq_num) < 0)
	{
#ifdef _DEBUG_
		printf(" 2. Seq# Validation : Dicard Packet \n");
#endif
		return -1;
	}

	// 3. ICV Validation
	if(current_sa->iv_mode == true)
	{
		size = endian16(packet->length) - (packet->ihl * 4) - ICV_LEN; 
		
		unsigned char* result = (unsigned char*)malloc(12);
		
		((Authentication*)(current_sa->auth))->authenticate(&(packet->body), size, result);
	
		if(memcmp(result, &(packet->body[size]), 12) != 0)
		{
#ifdef _DEBUG_
			printf(" 3. ICV Validation : Discard Packet \n");
#endif			
			return -1;
		}
	}

	switch(current_sa->protocol)
	{
		case IP_PROTOCOL_ESP :
			// 4. Decrypt
			size = endian16(packet->length) - (packet->ihl * 4) - ESP_HEADER_LEN; 
			
			if(current_sa->iv_mode == true)
				size -= ICV_LEN;
			
			((Cryptography*)(current_sa->crypto))->decrypt(esp, size); 
			
			// 5. ESP Header & Trailer Deletion
			int packet_protocol;
			int packet_len = endian16(packet->length) - ESP_HEADER_LEN - esp->body[size - 2] /* Padding */ - ESP_TRAILER_LEN;
			
			if(current_sa->mode == TRANSPORT)
			{
				packet_protocol = esp->body[size - 1];
				memmove(packet->body, esp->body, size);
			}
			else if(current_sa->mode == TUNNEL)
			{
				ip = (IP*)esp->body;
				packet_protocol = ip->protocol;
				packet_len -= (packet->ihl * 4);
				memmove(packet, esp->body, size);
			}
			
			packet->protocol = packet_protocol;
			packet->length = endian16(packet_len);
			
			if(current_sa->iv_mode == true) 
				packet->length = endian16(packet_len - ICV_LEN);
		
			break;
		
		case IP_PROTOCOL_AH : 	
			break;
		default : break;
	}
	
	// 6. SPD Lookup 
	if((current_sp = getSP(packet)) == NULL)
	{
#ifdef _DEBUG_
		printf(" 6. SPD Lookup : Discard packet \n");
#endif
		return -1;
	}

#ifdef _DEBUG_
	printf("Decrypted Packet : \n");
	
	Ether* ether = (Ether*)malloc(250);
	memmove(ether->payload, packet, 250) ; 
	int i;
	for(i = 1; i < 1 + endian16(packet->length); i++)
	{
		printf("%02x ", ether->payload[i - 1]); // Packet - IP Header 
		if( i % 16 == 0 )
			printf("\n");
	}
	printf("\n");

	free(ether);
#endif	
	return 0;
}

int encrypt(IP* packet)
{
	int size, body_len, padding_len, i;
	unsigned char* padding = NULL;
	current_sp = NULL;
	current_sa = NULL;

#ifdef _DEBUG_	
	printf("Encrypt Processing : \n");
#endif	
	// 1. SPD Lookup
	if((current_sp = getSP(packet)) == NULL)
	{
#ifdef _DEBUG_	
		printf(" 1. SPD Lookup : Bypass packet\n");
#endif		
		return -1;
	}

	// 2. SAD Lookup
	if((current_sa = findSA(current_sp->sa_pointer, current_sp, packet)) == NULL)
	{
#ifdef _DEBUG_	
		printf(" 2. SAD check : Discard packet\n");
#endif		
		return -1;
	}
	current_sa->crypto = get_cryptography(current_sa->esp_crypto_algorithm);
	current_sa->auth = get_authentication(current_sa->esp_auth_algorithm);

	switch(current_sa->protocol)
	{
		case IP_PROTOCOL_ESP :
			// 3. ESP Trailer Addition & Encrypt
			body_len = endian16(packet->length) - (packet->ihl * 4);
		
			if(current_sa->mode == TRANSPORT)
			{
				padding_len = (ESP_HEADER_LEN + body_len + 2) % 8;
				if(padding_len != 0)
					padding_len = 8 - (ESP_HEADER_LEN + body_len + 2) % 8;
			}
			else if(current_sa->mode == TUNNEL)
			{
				padding_len = (packet->ihl * 4 + ESP_HEADER_LEN + body_len + 2) % 16;
				if(padding_len != 0)
					padding_len = 16 - (packet->ihl * 4 + ESP_HEADER_LEN + body_len + 2) % 16;
			}

			padding = packet->body + body_len;
			
			for(i = 0; i < padding_len; i++)
				padding[i] = i + 1;
			
			packet->body[body_len + padding_len + 1] = packet->protocol;
			packet->body[body_len + padding_len] = padding_len;

			size = body_len + padding_len + 2;
			
			if(current_sa->mode == TUNNEL)
			{
				//  3.1 Inner IP Addition
				packet->ttl--;
				packet->checksum = 0;
				packet->checksum = endian16(checksum(packet, packet->ihl * 4));

				packet->body[body_len + padding_len + 1] = IP_PROTOCOL_IPV4;

				memmove(packet->body, packet, endian16(packet->length) + padding_len + ESP_TRAILER_LEN);
				// TODO : Hop Limit Check

				size += packet->ihl * 4;
			}
	
			((Cryptography*)(current_sa->crypto))->encrypt(packet->body, size);		
	
			// 4. IP Header Change & ESP Header Addition
			packet->protocol = IP_PROTOCOL_ESP;
			packet->length = endian16(endian16(packet->length) + ESP_HEADER_LEN + ESP_TRAILER_LEN + padding_len);
			
			//  4.1 IP Header Change
			if(current_sa->mode == TRANSPORT)
			{
			//	uint32_t temp = packet->source;	
			//	packet->source = packet->destination;
			//	packet->destination = temp;
			}
			else if(current_sa->mode == TUNNEL)
			{
				packet->length = endian16(endian16(packet->length) + packet->ihl * 4);
				packet->source = endian32(current_sp->t_src_ip);
				packet->destination = endian32(current_sp->t_dst_ip);
			}

			if(current_sa->iv_mode == true)
			{
				packet->length += endian16(ICV_LEN);
			}

			packet->ttl = endian8(64);
			packet->checksum = 0;
			packet->checksum = endian16(checksum(packet, packet->ihl * 4));
			
			// 4.2 ESP Header Addition
			memmove(packet->body + ESP_HEADER_LEN, packet->body, endian16(packet->length) - packet->ihl * 4 - ESP_HEADER_LEN);
			
			ESP* esp = (ESP*)packet->body;
			esp->spi = endian32(current_sa->spi);
			esp->iv = current_sa->iv;	
			
			// 5. Seq# Validation 
			esp->seq_num = endian32(++current_sa->window->seq_counter);
			// TODO : Seq# Overflow Check
			
			// 6. ICV Calculation
			if(current_sa->iv_mode == true)
			{
				size = endian16(packet->length) - (packet->ihl * 4) - ICV_LEN; 
				unsigned char* result = &(packet->body[size]);
				((Authentication*)(current_sa->auth))->authenticate(&(packet->body), size, result);
			}
			break;
		case IP_PROTOCOL_AH :
			break;
		default : 
			break;
	}


#ifdef _DEBUG_	
	printf("Encrypted Packet : \n");

	Ether* ether1 = (Ether*)malloc(250);
	memmove(ether1->payload, packet, 250) ; 
	
	for(i = 1; i < 1 + endian16(packet->length) ; i++) 
	{
		printf("%02x ", ether1->payload[i - 1]); // Packet - IP Header 
		if( i % 16 == 0 )
			printf("\n");
	}
	printf("\n");
	
	free(ether1);
#endif
	return 0;
}

