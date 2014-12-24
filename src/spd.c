#include "spd.h"

// KEY : src_ip arrange, dst_ip arrange, xpt_protocol(upperspec), (src_port), (dst_port) TODO : port
SP* getSP(IP* packet)
{
	SP* tmp = NULL;

	list_for_each_entry(tmp, &((spd.sp_list)->list), list)
	{
//		printf("packet->source : %p, spd->source : %p\n",(endian32(packet->source) & tmp->src_mask), (tmp->src_ip & tmp->src_mask));
		if((endian32(packet->source) & tmp->src_mask) == (tmp->src_ip & tmp->src_mask))
		{
//			printf("packet->destination : %p, spd->destination : %p\n",(endian32(packet->destination) & tmp->dst_mask), (tmp->dst_ip & tmp->dst_mask));
			if((endian32(packet->destination) & tmp->dst_mask) == (tmp->dst_ip & tmp->dst_mask))
			{
//				printf("spd->upperspec : %d, packet->protocol : %d\n", tmp->upperspec, packet->protocol);
				if(tmp->upperspec == IP_PROTOCOL_ANY)
					return tmp;
				else if(packet->protocol == tmp->upperspec)
					return tmp;
			}
		}
	}

	return NULL;
}

int setSA_pointer(SA* sa)
{
	SP* tmp = NULL;

	list_for_each_entry(tmp, &((spd.sp_list)->list), list)
	{
		if(tmp->mode == TRANSPORT)
		{
			if((sa->src_ip & tmp->src_mask) == (tmp->src_ip & tmp->src_mask))
			{
				if((sa->dst_ip & tmp->dst_mask) == (tmp->dst_ip & tmp->dst_mask))
				{
					if(sa->protocol == tmp->protocol)
					{
						if(tmp->sa_pointer == NULL)
						{
							//sa->bundle_list = sa;

							//INIT_LIST_HEAD(&((sa->bundle_list)->list));
							tmp->sa_pointer = sa;
							return 0;
						}
						else
						{
							//list_add_head(&(sa->list), &(tmp->sa_pointer->bundle_list->list));
							return 0;
						}
					}
				}
			}
		}
		else if(tmp->mode == TUNNEL)
		{
			if(sa->src_ip == tmp->t_src_ip)
			{
				if(sa->dst_ip == tmp->t_dst_ip)
				{
					if(sa->protocol == tmp->protocol)
					{
						if(tmp->sa_pointer == NULL)
						{
							//sa->bundle_list = sa;
							//INIT_LIST_HEAD(&((sa->bundle_list)->list));
							tmp->sa_pointer = sa;
							return 0;
						}
						else
						{
							//list_add_head(&(sa->list), &(tmp->sa_pointer->bundle_list->list));
							return 0;
						}

					}
				}
			}
		}
	}

	return -1;		
}

