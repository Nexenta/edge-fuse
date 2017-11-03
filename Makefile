#
# Determine the platform first
UNAME := $(shell uname -s)
DISTID := $(shell echo $$(. /etc/os-release; echo $$ID | tr '[A-Z]' '[a-z]'))

#
# Activate ASAN by exporing this env variable:
#
# export ASAN_OPTIONS=symbolize=1:abort_on_error=1:disable_core=1:alloc_dealloc_mismatch=0:detect_leaks=1
#
#ASAN_CPPFLAGS=-fsanitize=address -fno-omit-frame-pointer -fno-common
#ASAN_LDFLAGS=-fsanitize=address -fno-omit-frame-pointer -fno-common -lasan
ASAN_CPPFLAGS=
ASAN_LDFLAGS=

ifeq ($(UNAME), Darwin)

MAIN_CFLAGS :=  -g -O2 -Wall -std=c99 -D_FILE_OFFSET_BITS=64 $(ASAN_CPPFLAGS)
CC = gcc
CFLAGS += -I/usr/local/opt/openssl/include
LDFLAGS = -lgnutls -lfuse 

else

MAIN_CFLAGS :=  -g -O2 -Wall -std=c99 $(shell pkg-config fuse --cflags) $(ASAN_CPPFLAGS)
MAIN_CPPFLAGS := -Wall -Wno-unused-function -Wconversion -Wtype-limits -DUSE_AUTH -D_XOPEN_SOURCE=700 -D_ISOC99_SOURCE $(ASAN_LDFLAGS)
THR_LDFLAGS := -lpthread
GNUTLS_VERSION := 2.10
MAIN_LDFLAGS := $(shell pkg-config fuse --libs | sed -e s/-lrt// -e s/-ldl// -e s/-pthread// -e "s/  / /g")
intermediates =

ifeq ($(shell pkg-config --atleast-version $(GNUTLS_VERSION) gnutls ; echo $$?), 0)
    CERT_STORE := /etc/ssl/certs/ca-certificates.crt
    CPPFLAGS := -DUSE_SSL $(shell pkg-config gnutls --cflags) -DCERT_STORE=\"$(CERT_STORE)\"
    LDFLAGS := $(shell pkg-config gnutls --libs)
else
        $(info GNUTLS version at least $(GNUTLS_VERSION) required for SSL support.)
endif

endif

binbase = edgefs

binaries = $(binbase)

manpages = $(addsuffix .1,$(binaries))

intermediates += $(addsuffix .xml,$(manpages))

targets = $(binaries) $(manpages)

all: $(targets)

edgefs: edgefs.c
	$(CC) $(MAIN_CPPFLAGS) $(CPPFLAGS) $(MAIN_CFLAGS) $(CFLAGS) edgefs.c $(MAIN_LDFLAGS) $(THR_LDFLAGS) $(LDFLAGS) -o $@

edgefs%.1: edgefs.1
	ln -sf edgefs.1 $@

clean:
	rm -f $(targets) $(intermediates)
	rm -rf ./$(pkg_dir)

%.1: %.1.txt
	a2x -f manpage $<

ifeq ($(DISTID), ubuntu)

# Rules to automatically make a Debian package

pkg_dir = pkgdeb
package = $(shell dpkg-parsechangelog | grep ^Source: | sed -e s,'^Source: ',,)
version = $(shell dpkg-parsechangelog | grep ^Version: | sed -e s,'^Version: ',, -e 's,-.*,,')
revision = $(shell dpkg-parsechangelog | grep ^Version: | sed -e -e 's,.*-,,')
architecture = $(shell dpkg --print-architecture)
tar_dir = $(package)-$(version)
tar_gz   = $(tar_dir).tar.gz
unpack_dir  = $(pkg_dir)/$(tar_dir)
orig_tar_gz = $(pkg_dir)/$(package)_$(version).orig.tar.gz
pkg_deb_src = $(pkg_dir)/$(package)_$(version)-$(revision)_source.changes
pkg_deb_bin = $(pkg_dir)/$(package)_$(version)-$(revision)_$(architecture).changes

deb_pkg_key = CB8C5858

debclean:
	rm -rf $(pkg_dir)

deb: debsrc debbin

debbin: $(unpack_dir)
	cd $(unpack_dir) && dpkg-buildpackage -b -k$(deb_pkg_key)

debsrc: $(unpack_dir)
	cd $(unpack_dir) && dpkg-buildpackage -S -k$(deb_pkg_key)

$(unpack_dir): $(orig_tar_gz)
	tar -zxf $(orig_tar_gz) -C $(pkg_dir)

$(pkg_dir):
	mkdir $(pkg_dir)

$(pkg_dir)/$(tar_gz): $(pkg_dir)
	git archive --format=tar.gz --prefix=$(package)-$(version)/ -o $(pkg_dir)/$(tar_gz) HEAD

$(orig_tar_gz): $(pkg_dir)/$(tar_gz)
	ln -s $(tar_gz) $(orig_tar_gz)

else

pkg_dir = SOURCES
package = $(binbase)
version = $(shell cat edgefs.spec |awk '/Version:/{print $$2}')
tar_gz = $(package)-$(version).tar.gz

rpm: rpmbin

rpmbin: $(pkg_dir)/$(tar_gz)
	rpmbuild --quiet --define "_topdir `pwd`" -ba 'edgefs.spec'

$(pkg_dir):
	mkdir $(pkg_dir)

$(pkg_dir)/$(tar_gz): $(pkg_dir)
	git archive --format=tar.gz --prefix=$(package)-$(version)/ -o $(pkg_dir)/$(tar_gz) HEAD

endif
