.PHONY: run all depend clean
#-nostdinc 
CFLAGS = -I ../../include -I -O2 -Wall -m64 -ffreestanding -std=gnu99 -Werror #-D_GW1_ 

DIR = obj 

OBJS = obj/sad.o obj/spd.o obj/crypto.o obj/auth.o obj/main.o obj/window.o obj/ipsec.o obj/receiver.o obj/setkey.o 
#OBJS = obj/SA.o obj/SAD.o obj/SPD.o obj/authenticator.o obj/decryptor.o obj/encryptor.o obj/s_window.o obj/IPSec_module.o obj/main.o

LIBS = --start-group ../../lib/libpacketngin.a ../../lib/libcrypto.a ../../lib/libssl.a --end-group

all: $(OBJS)
	ld -melf_x86_64 -nostdlib -e main -o main $^ $(LIBS)

obj/%.o: src/%.c
	mkdir -p $(DIR)
	gcc $(CFLAGS) -c -o $@ $<

#depend : 
#	gccmakedep $(CFALGS) src/*.c 

clean:
	rm -rf obj
	rm -f main

run: all 
	../../bin/console script