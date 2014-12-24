#ifndef __IPSEC_H__
#define __IPSEC_H__

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <net/ip.h>
#include <net/checksum.h>
#include <net/ether.h>
#include "spd.h"
#include "sad.h"
#include "crypto.h"
#include "auth.h"
#include "receiver.h"
#include "clock.h"
#include "packetviewer.h"


#define true 	1
#define false 	0

void init_list();
int encrypt(IP* packet);
int decrypt(IP* packet);

SP* current_sp;
SA* current_sa;

extern Window window;

#endif /* __IPSEC_H__ */



