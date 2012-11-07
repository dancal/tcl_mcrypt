#2007.11.25 created by dancal

CC = gcc
INC = -I./ext -I./libmcrypt/modules/modes/ -Ilibmcrypt/modules/algorithms -Ilibmcrypt/lib -Ilibmcrypt/
LIBS = -L./ext
#CFLAGS = -O3 -g $(INC) -fPIC -o libmcrypt.la
CFLAGS = -O3 -g $(INC) -fPIC

OBJS = tcl_mcrypt.o ext/tcl_compat.o ext/php_compat.o ./libmcrypt/modules/modes/cbc.o ./libmcrypt/modules/modes/cfb.o ./libmcrypt/modules/modes/ctr.o ./libmcrypt/modules/modes/ecb.o ./libmcrypt/modules/modes/ncfb.o ./libmcrypt/modules/modes/nofb.o ./libmcrypt/modules/modes/ofb.o ./libmcrypt/modules/modes/stream.o ./libmcrypt/modules/algorithms/cast-128.o ./libmcrypt/modules/algorithms/gost.o ./libmcrypt/modules/algorithms/rijndael-128.o ./libmcrypt/modules/algorithms/twofish.o ./libmcrypt/modules/algorithms/arcfour.o ./libmcrypt/modules/algorithms/cast-256.o ./libmcrypt/modules/algorithms/loki97.o ./libmcrypt/modules/algorithms/rijndael-192.o ./libmcrypt/modules/algorithms/saferplus.o ./libmcrypt/modules/algorithms/wake.o ./libmcrypt/modules/algorithms/blowfish-compat.o ./libmcrypt/modules/algorithms/des.o ./libmcrypt/modules/algorithms/rijndael-256.o ./libmcrypt/modules/algorithms/serpent.o ./libmcrypt/modules/algorithms/xtea.o ./libmcrypt/modules/algorithms/blowfish.o ./libmcrypt/modules/algorithms/enigma.o ./libmcrypt/modules/algorithms/rc2.o ./libmcrypt/modules/algorithms/tripledes.o libmcrypt/lib/mcrypt_extra.o libmcrypt/lib/mcrypt.o libmcrypt/lib/bzero.o libmcrypt/lib/xmemory.o libmcrypt/lib/mcrypt_modules.o libmcrypt/lib/win32_comp.o libmcrypt/lib/mcrypt_threads.o libmcrypt/lib/mcrypt_symb.o

SRCS = tcl_mcrypt.c ext/tcl_compat.c ext/php_compat.c ./libmcrypt/modules/modes/cbc.c ./libmcrypt/modules/modes/cfb.c ./libmcrypt/modules/modes/ctr.c ./libmcrypt/modules/modes/ecb.c ./libmcrypt/modules/modes/ncfb.c ./libmcrypt/modules/modes/nofb.c ./libmcrypt/modules/modes/ofb.c ./libmcrypt/modules/modes/stream.c ./libmcrypt/modules/algorithms/cast-128.c ./libmcrypt/modules/algorithms/gost.c ./libmcrypt/modules/algorithms/rijndael-128.c ./libmcrypt/modules/algorithms/twofish.c ./libmcrypt/modules/algorithms/arcfour.c ./libmcrypt/modules/algorithms/cast-256.c ./libmcrypt/modules/algorithms/loki97.c ./libmcrypt/modules/algorithms/rijndael-192.c ./libmcrypt/modules/algorithms/saferplus.c ./libmcrypt/modules/algorithms/wake.c ./libmcrypt/modules/algorithms/blowfish-compat.c ./libmcrypt/modules/algorithms/des.c ./libmcrypt/modules/algorithms/rijndael-256.c ./libmcrypt/modules/algorithms/serpent.c ./libmcrypt/modules/algorithms/xtea.c ./libmcrypt/modules/algorithms/blowfish.c ./libmcrypt/modules/algorithms/enigma.c ./libmcrypt/modules/algorithms/rc2.c ./libmcrypt/modules/algorithms/tripledes.c libmcrypt/lib/mcrypt_extra.c libmcrypt/lib/mcrypt.c libmcrypt/lib/bzero.c libmcrypt/lib/xmemory.c libmcrypt/lib/mcrypt_modules.c libmcrypt/lib/win32_comp.c libmcrypt/lib/mcrypt_threads.c libmcrypt/lib/mcrypt_symb.c

TARGET = libmcrypt1.0.so

all : $(TARGET)
$(TARGET) : $(OBJS)
	$(CC) -shared -Wl,-soname,$@ -o $@ $(OBJS) -dl -lc -ltcl -lnsl -lm -lcrypt -lltdl -L.

dep :
	gccmakedep $(INC) $(SRCS)

clean :
	rm -rf $(OBJS) $(TARGET) core
