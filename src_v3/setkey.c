#include "setkey.h"

// TODO : Extensions addition, Duplciation check
int setkey_add(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol, uint32_t spi, uint8_t extensions, uint8_t crypto_algorithm, uint8_t auth_algorithm, uint64_t crypto_key[], uint64_t auth_key[])
{
	SA* sa = (SA*)malloc(sizeof(SA));

	sa->src_ip = src_ip;
	sa->dst_ip = dst_ip;
	sa->protocol = protocol;
	sa->spi = spi;
	sa->mode = extensions; // TODO Here
	sa->esp_crypto_algorithm = crypto_algorithm;
	sa->esp_auth_algorithm = auth_algorithm;

	switch(protocol)
	{
		case IP_PROTOCOL_ESP : 
			if(crypto_algorithm != 0)
			{
				sa->esp_crypto_key[0] = crypto_key[0];
				sa->esp_crypto_key[1] = crypto_key[1];
				sa->esp_crypto_key[2] = crypto_key[2];
				printf("crypto key[0] : %lx\n", crypto_key[0]);
			//	memecpy(sa->esp_crypto_key, crypto_key, 24);
			}
			if(auth_algorithm != 0)
			{
				sa->iv_mode = true;
				sa->esp_auth_key[0] = auth_key[0];
				sa->esp_auth_key[1] = auth_key[1];
			}
		break;
			
		case IP_PROTOCOL_AH :
			sa->ah_key[0] = auth_key[0];
			sa->ah_key[1] = auth_key[1];
		break;
		
		default : break;
	}

	sa->window = (Window*)malloc(sizeof(Window));
	memset(sa->window, 0x0, sizeof(Window));

	if(setSA_pointer(sa) < 0)
		printf("No matched SP for new SA\n");

	list_add_head(&(sa->list), &((sad.sa_list)->list));

	return 0;
}

int setkey_get(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol, uint32_t spi)
{
	SA* tmp = NULL;
	
	list_for_each_entry(tmp, &((sad.sa_list)->list), list)
	{
		if(spi == tmp->spi)
		{
			if(protocol == tmp->protocol)
			{
				if(src_ip == tmp->src_ip)
				{
					if(dst_ip == tmp->dst_ip)
					{
						// ...					
					}
				}
			}
		}
	}

	return 0;
}

int setkey_delete(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol, uint32_t spi)
{
 	SA* tmp;

	list_for_each_entry(tmp, &((sad.sa_list)->list), list)
	{
		if(spi == tmp->spi)
		{
			if(protocol == tmp->protocol)
			{
				if(src_ip == tmp->src_ip)
				{
					if(dst_ip == tmp->dst_ip)
					{
						free(tmp->window);
						list_del(&(tmp->list));
						free(tmp);

						return 0;
					}
				}
			}
		}
	}

	printf("No matched SA for deleting\n");

	return 0;
}

int setkey_deleteall(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol)
{
 	SA* tmp;

	list_for_each_entry(tmp, &((sad.sa_list)->list), list)
	{
		if(protocol == tmp->protocol)
		{
			if(src_ip == tmp->src_ip)
			{
				if(dst_ip == tmp->dst_ip)
				{
					free(tmp->window);				
					list_del(&(tmp->list));
					free(tmp);
				}
			}
		}
	}
	
	printf("No matched SA for deleting\n");
	
	return 0;
}

int setkey_flush(uint8_t protocol)
{
 	SA* tmp;

	list_for_each_entry(tmp, &((sad.sa_list)->list), list)
	{
		if(protocol == tmp->protocol)
		{
			list_del(&(tmp->list));
			free(tmp);
		}
	}
	return 0;
}

int setkey_dump(uint8_t protocol)
{
	printf("=== SETKEY_DUMP ===\n");
 	
	SA* tmp;
	
	list_for_each_entry(tmp, &((sad.sa_list)->list), list)
	{
		if(protocol == 0 || protocol == tmp->protocol)
		{
			printf("SPI : %x\n", tmp->spi);
			printf("Source IP : %x Destination IP : %x\n", tmp->src_ip, tmp->dst_ip);
			printf("Source Port : %d Destination Port : %d\n", tmp->src_port, tmp->dst_port);
			printf("Protocol : %x\n", tmp->protocol);
			printf("ESP Crypto Algorithm : %x\n", tmp->esp_crypto_algorithm); 
			printf("ESP Auth Algorithm : %x\n", tmp->esp_auth_algorithm); 
			printf("Mode ( 1: Transport, 2: Tunnel ) : %d\n", tmp->mode);
			printf("Crypto Key : 0x%lx%lx%lx\n", tmp->esp_crypto_key[0], tmp->esp_crypto_key[1], tmp->esp_crypto_key[2]);
			printf("\n");
		}
	}
	return 0;
}

// TODO : Duplication check
int setkey_spdadd(uint32_t src_ip, uint32_t dst_ip, uint32_t src_mask, uint32_t dst_mask, uint16_t src_port, uint16_t dst_port, uint8_t upperspec, uint8_t direction, uint8_t action, uint8_t protocol, uint8_t mode, uint32_t t_src_ip, uint32_t t_dst_ip, uint8_t level)
{
	SP* sp = (SP*)malloc(sizeof(SP));

	sp->src_ip = src_ip;
	sp->dst_ip = dst_ip;
	sp->src_mask = src_mask;
	sp->dst_mask = dst_mask;
	sp->src_port = src_port;
	sp->dst_port = dst_port;
	sp->upperspec = upperspec;
	sp->direction = direction;
	sp->action = action;
	sp->protocol = protocol;
	sp->mode = mode;
	sp->t_src_ip = t_src_ip;
	sp->t_dst_ip = t_dst_ip;
	sp->level = level;
	sp->sa_pointer = NULL;

	list_add_head(&(sp->list), &((spd.sp_list)->list));

//	printf("src_mask : %x dst_mask : %x\n", sp->src_mask, sp->dst_mask);

	//SP* tmp;
	
//	printf("spd address : %x\n", &spd);
/*
	list_for_each_entry(tmp, &((spd.sp_list)->list), list)
	{
		printf("spd_source : %x spd_dst : %x\n", tmp->src_ip, tmp->dst_ip);
	}*/
	return 0;
}

int setkey_spdupdate(uint32_t src_ip, uint32_t dst_ip, uint32_t src_mask, uint32_t dst_mask, uint16_t src_port, uint16_t dst_port, uint8_t upperspec, uint8_t direction, uint8_t action)
{
	// Range ?
	return 0;
}

int setkey_spddelete(uint32_t src_ip, uint32_t dst_ip, uint32_t src_mask, uint32_t dst_mask, uint16_t src_port, uint16_t dst_port, uint8_t upperspec, uint8_t direction, uint8_t action)
{
	// Range ?
	return 0;
}

int setkey_spdflush()
{
 	SP* tmp;

	list_for_each_entry(tmp, &((spd.sp_list)->list), list)
	{
		list_del(&(tmp->list));
		free(tmp);
	}
	return 0;
}

int setkey_spddump()
{
	printf("=== SETKEY_SPDDUMP ===\n");
	
	SP* tmp;
	
	list_for_each_entry(tmp, &((spd.sp_list)->list), list)
	{
		printf("Source IP : %x Destination IP : %x\n", tmp->src_ip, tmp->dst_ip);
		printf("Source IP : %x Destination IP : %x (Tunnel)\n ", tmp->t_src_ip, tmp->t_dst_ip);
		printf("Source Mask : %x Destination Mask : %x\n", tmp->src_mask, tmp->dst_mask);
		printf("Source Port : %d Destination Port : %d\n", tmp->src_port, tmp->dst_port);
		printf("Action : %x\n", tmp->action);
		printf("Protocol : %x\n", tmp->protocol);
		printf("Mode ( 1: Transport, 2: Tunnel ) : %d\n", tmp->mode);
		printf("Upperspec : %x\n", tmp->upperspec);
		printf("Direction ( 1: IN,  2: OUT ) : %d \n", tmp->direction);
		printf("Level : %x\n", tmp->level);
		printf("SA Pointer (SPI) : %x\n", tmp->sa_pointer->spi);
		printf("\n");
	}
	return 0;
}