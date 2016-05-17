#########define
CC = gcc
CFLAGS = -Wall -g -O2
#CFLAGS = -Wall
INCLUDES = -I/usr/local/include/evhtp -I/usr/include/GraphicsMagick
LIBS = -levent -levent_openssl -levent_pthreads -lssl -lcrypto -levhtp -lpthread -lm -lhiredis -lmemcached -llua -lMagickWand

all: objs/ox
.PHONY: all

#########
objs/ox: objs/ox.o \
		objs/ox_cbs.o \
		objs/ox_access.o \
		objs/ox_img.o \
		objs/ox_gm.o \
		objs/ox_lua.o \
		objs/ox_memc.o \
		objs/ox_db.o \
		objs/ox_md5.o \
		objs/ox_log.o \
		objs/ox_slock.o \
		objs/ox_utils.o \
		objs/ox_string.o \
		objs/multipart_parser.o \
		objs/cJSON.o

	$(CC) -o objs/ox \
		objs/ox.o \
		objs/ox_cbs.o \
		objs/ox_access.o \
		objs/ox_img.o \
		objs/ox_gm.o \
		objs/ox_lua.o \
		objs/ox_memc.o \
		objs/ox_db.o \
		objs/ox_md5.o \
		objs/ox_log.o \
		objs/ox_slock.o \
		objs/ox_utils.o \
		objs/ox_string.o \
		objs/multipart_parser.o \
		objs/cJSON.o \
		$(LIBS)

#########
#  core  #
#########
objs/ox.o: src/ox.c

	$(CC) -c $(CFLAGS) $(INCLUDES) \
		-o objs/ox.o \
		src/ox.c

objs/ox_cbs.o: src/ox_cbs.c

	$(CC) -c $(CFLAGS) $(INCLUDES) \
		-o objs/ox_cbs.o \
		src/ox_cbs.c

objs/ox_access.o: src/ox_access.c

	$(CC) -c $(CFLAGS) $(INCLUDES) \
		-o objs/ox_access.o \
		src/ox_access.c

objs/ox_img.o: src/ox_img.c

	$(CC) -c $(CFLAGS) $(INCLUDES) \
		-o objs/ox_img.o \
		src/ox_img.c

objs/ox_gm.o: src/ox_gm.c

	$(CC) -c $(CFLAGS) $(INCLUDES) \
		-o objs/ox_gm.o \
		src/ox_gm.c

objs/ox_lua.o: src/ox_lua.c

	$(CC) -c $(CFLAGS) $(INCLUDES) \
		-o objs/ox_lua.o \
		src/ox_lua.c

objs/ox_memc.o: src/ox_memc.c

	$(CC) -c $(CFLAGS) $(INCLUDES) \
		-o objs/ox_memc.o \
		src/ox_memc.c

objs/ox_db.o: src/ox_db.c

	$(CC) -c $(CFLAGS) $(INCLUDES) \
		-o objs/ox_db.o \
		src/ox_db.c

objs/ox_md5.o: src/ox_md5.c

	$(CC) -c $(CFLAGS) $(INCLUDES) \
		-o objs/ox_md5.o \
		src/ox_md5.c

objs/ox_log.o: src/ox_log.c

	$(CC) -c $(CFLAGS) $(INCLUDES) \
		-o objs/ox_log.o \
		src/ox_log.c

objs/ox_slock.o: src/ox_slock.c

	$(CC) -c $(CFLAGS) $(INCLUDES) \
		-o objs/ox_slock.o \
		src/ox_slock.c

objs/ox_utils.o: src/ox_utils.c

	$(CC) -c $(CFLAGS) $(INCLUDES) \
		-o objs/ox_utils.o \
		src/ox_utils.c

objs/ox_string.o: src/ox_string.c

	$(CC) -c $(CFLAGS) $(INCLUDES) \
		-o objs/ox_string.o \
		src/ox_string.c

objs/multipart_parser.o: src/multipart-parser/multipart_parser.c

	$(CC) -c $(CFLAGS) $(INCLUDES) \
		-o objs/multipart_parser.o \
		src/multipart-parser/multipart_parser.c

objs/cJSON.o: src/cjson/cJSON.c

	$(CC) -c $(CFLAGS) $(INCLUDES) \
		-o objs/cJSON.o \
		src/cjson/cJSON.c

#########
#  clean #
#########
clean:
	rm -f objs/ox
	rm -f objs/*.o
