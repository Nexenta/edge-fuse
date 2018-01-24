TARGET_LIB = libcachemap.so.0.0
TARGET_SRCS = mdb.c midl.c lz4.c filemap.c cachemap.c
#
# Activate by exporing this env variable:
#
# export ASAN_OPTIONS=symbolize=1:abort_on_error=1:disable_core=1:alloc_dealloc_mismatch=0:detect_leaks=1
#
#ASAN_CPPFLAGS=-fsanitize=address -fno-omit-frame-pointer -fno-common
#ASAN_LDFLAGS=-fsanitize=address -fno-omit-frame-pointer -fno-common -lasan
CFLAGS += -fPIC -Wall -Wextra -Wno-unused -O3 -pthread -g -I. -L. $(ASAN_CPPFLAGS)
LDFLAGS += -L. $(ASAN_LDFLAGS)

TARGET_OBJS = $(TARGET_SRCS:.c=.o)

.PHONY: all
all: ${TARGET_LIB} cachemap_test

$(TARGET_LIB): $(TARGET_OBJS)
	gcc -shared -o $@ $^ $(LDFLAGS)
	gcc -shared -Wl,-soname,$(TARGET_LIB) $^ $(LDFLAGS) -o $@
	ln -sf libcachemap.so.0.0 libcachemap.so

cachemap_test: cachemap_test.c $(TARGET_LIB)
	gcc $(CFLAGS) -o $@ $^ -lcachemap

pktrecv: pktrecv.c $(TARGET_LIB)
	gcc $(CFLAGS) -o $@ $^ -lcachemap

clean:
	rm -f $(TARGET_LIB) cachemap_test *.o *.so
