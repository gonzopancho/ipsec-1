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
			}
			if(auth_algorithm != 0)
			{
				sa->iv_mode = true;
				sa->esp_auth_key[0] = auth_key[0];
				sa->esp_auth_key[1] = auth_key[1];
				sa->esp_auth_key[2] = auth_key[2];
				sa->esp_auth_key[3] = auth_key[3];
				sa->esp_auth_key[4] = auth_key[4];
				sa->esp_auth_key[5] = auth_key[5];
				sa->esp_auth_key[6] = auth_key[6];
				sa->esp_auth_key[7] = auth_key[7];
			}
		break;
			
		case IP_PROTOCOL_AH :
				sa->ah_key[0] = auth_key[0];
				sa->ah_key[1] = auth_key[1];
				sa->ah_key[2] = auth_key[2];
				sa->ah_key[3] = auth_key[3];
				sa->ah_key[4] = auth_key[4];
				sa->ah_key[5] = auth_key[5];
				sa->ah_key[6] = auth_key[6];
		break;
		
		default : break;
	}

	sa->window = (Window*)malloc(sizeof(Window));
	memset(sa->window, 0x0, sizeof(Window));

	if(setSA_pointer(sa) < 0)
		printf("No matched SP for new SA\n");

	list_add_head(&(sa->list), &((sad.sa_list)->list));
	sad.size++;

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
						printf("SPI : %x\n", tmp->spi);
						printf("Source IP : %x Destination IP : %x\n", tmp->src_ip, tmp->dst_ip);
						printf("Source Port : %d Destination Port : %d\n", tmp->src_port, tmp->dst_port);
						printf("Protocol : %x\n", tmp->protocol);
						printf("ESP Crypto Algorithm : %x\n", tmp->esp_crypto_algorithm); 
						printf("ESP Auth Algorithm : %x\n", tmp->esp_auth_algorithm); 
						printf("Mode ( 1: Transport, 2: Tunnel ) : %d\n", tmp->mode);
						printf("Crypto Key : 0x%lx%lx%lx\n", tmp->esp_crypto_key[0], tmp->esp_crypto_key[1], tmp->esp_crypto_key[2]);
						printf("Auth Key : 0x%lx%lx%lx\n", tmp->esp_auth_key[0], tmp->esp_auth_key[1], tmp->esp_auth_key[2]);
						printf("\n");
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
 	SA* tmp = 0;
	struct list_head* pos = 0;
	struct list_head* q = 0;

	if(sad.size == 0)
		return 0;

	for (pos = (&((sad.sa_list)->list))->next, q = pos->next; pos != (&((sad.sa_list)->list)); pos = q, q = pos->next)
	//list_for_each_safe(pos, q, &((sad.sa_list)->list));
	{
		if(protocol == 0 || protocol == tmp->protocol)
		{
			tmp = list_entry(pos, SA, list);
			list_del(pos);
			free(tmp);
			sad.size--;
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
			printf("Auth Key : 0x%lx%lx%lx\n", tmp->esp_auth_key[0], tmp->esp_auth_key[1], tmp->esp_auth_key[2]);
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

	return 0;
}

int setkey_spdupdate(uint32_t src_ip, uint32_t dst_ip, uint32_t src_mask, uint32_t dst_mask, uint16_t src_port, uint16_t dst_port, uint8_t upperspec, uint8_t direction, uint8_t action)
{
	SP* tmp = NULL;

	list_for_each_entry(tmp, &((spd.sp_list)->list), list)
	{
		if((src_ip & src_mask) == (tmp->src_ip & tmp->src_mask))
		{
			if((dst_ip & dst_mask) == (tmp->dst_ip & tmp->dst_mask))
			{
				if((src_port == tmp->src_port) && (dst_port == tmp->dst_port))
				{
					if(upperspec == tmp->upperspec)
					{
						tmp->direction = direction;
						tmp->action = action;
					}
				}
			}
		}
	}
	
	return 0;
}

int setkey_spddelete(uint32_t src_ip, uint32_t dst_ip, uint32_t src_mask, uint32_t dst_mask, uint16_t src_port, uint16_t dst_port, uint8_t upperspec, uint8_t direction, uint8_t action)
{
/*
	SP* tmp = NULL;

	list_for_each_entry(tmp, &((spd.sp_list)->list), list)
	{
		if((src_ip & src_mask) == (tmp->src_ip & tmp->src_mask))
		{
			if((dst_ip & dst_mask) == (tmp->dst_ip & tmp->dst_mask))
			{
				if((src_port == tmp->src_port) && (dst_port == tmp->dst_port))
				{
					tmp->upperspec = upperspec;
					tmp->direction = direction;
					tmp->action = action;
				}
			}
		}
	}
*/	
	return 0;
}

int setkey_spdflush()
{
 	SP* tmp = 0;
	struct list_head* pos;
	struct list_head* q;

	if(spd.size == 0)
		return 0;
	/*
	list_for_each_entry(tmp, &((spd.sp_list)->list), list)
	{
		printf("tmp list : %p\n", &(tmp->list));
		list_del(&(tmp->list));
		free(tmp);
	}*/

	// TODO : Macro debugging
	for (pos = (&((spd.sp_list)->list))->next, q = pos->next; pos != (&((spd.sp_list)->list)); pos = q, q = pos->next)
//	list_for_each_safe(pos, q, &((spd.sp_list)->list));
	{
		/*printf("head->next : %p\n", (&((spd.sp_list)->list))->next);
		
		printf("tmp : %p\n", tmp);
		printf("pos : %p\n", pos);
		printf("q : %p\n", q);
		tmp = list_entry(pos, SP, list);
		printf("tmp : %p\n", tmp);
		printf("pos : %p\n", pos);
		printf("pos->next : %p spd.sp_list->list : %p\n", pos->next, &((spd.sp_list)->list));*/
		list_del(pos);
		free(tmp);
		spd.size--;
	}
//	printf("spd.sp_list->list after : %p\n",&((spd.sp_list)->list));
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
	//	printf("SA Pointer (SPI) : %x\n", tmp->sa_pointer->spi);
		printf("\n");
	}
	return 0;
}
