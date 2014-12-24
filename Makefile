.PHONY: run all clean
#-nostdinc 
CFLAGS = -I ../../include -I -O0 -Wall -m64 -ffreestanding -std=gnu99 -Werror -D_GW1_ -D_TRANSPORT_ #-D_DEBUG_ #-D_PACKETVIEWER_   

DIR = obj 

OBJS = obj/sad.o obj/spd.o obj/crypto.o obj/auth.o obj/test.o obj/window.o obj/ipsec.o obj/receiver.o obj/setkey.o obj/clock.o obj/packetviewer.o

LIBS = --start-group ../../lib/libpacketngin.a ../../lib/libcrypto.a ../../lib/libssl.a --end-group

all: $(OBJS)
	ld -melf_x86_64 -nostdlib -e main -o main $^ $(LIBS)

obj/%.o: src/%.c
	mkdir -p $(DIR)
	gcc $(CFLAGS) -c -o $@ $<

clean:
	rm -rf obj
	rm -f main

run: all 
	./console script
#	../../bin/console script
