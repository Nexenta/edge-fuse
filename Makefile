MAIN_CFLAGS :=  -g -Os -Wall $(shell pkg-config fuse --cflags)
MAIN_CPPFLAGS := -Wall -Wno-unused-function -Wconversion -Wtype-limits -DUSE_AUTH -D_XOPEN_SOURCE=700 -D_ISOC99_SOURCE
THR_CPPFLAGS := -DUSE_THREAD
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

binbase = edgefs

binaries = $(binbase)

manpages = $(addsuffix .1,$(binaries))

intermediates += $(addsuffix .xml,$(manpages))

targets = $(binaries) $(manpages)

all: $(targets)

edgefs: edgefs.c
	$(CC) $(MAIN_CPPFLAGS) $(CPPFLAGS) $(MAIN_CFLAGS) $(CFLAGS) edgefs.c $(MAIN_LDFLAGS) $(LDFLAGS) -o $@

edgefs%.1: edgefs.1
	ln -sf edgefs.1 $@

clean:
	rm -f $(targets) $(intermediates)

%.1: %.1.txt
	a2x -f manpage $<

# Rules to automatically make a Debian package

package = $(shell dpkg-parsechangelog | grep ^Source: | sed -e s,'^Source: ',,)
version = $(shell dpkg-parsechangelog | grep ^Version: | sed -e s,'^Version: ',, -e 's,-.*,,')
revision = $(shell dpkg-parsechangelog | grep ^Version: | sed -e -e 's,.*-,,')
architecture = $(shell dpkg --print-architecture)
tar_dir = $(package)-$(version)
tar_gz   = $(tar_dir).tar.gz
pkg_deb_dir = pkgdeb
unpack_dir  = $(pkg_deb_dir)/$(tar_dir)
orig_tar_gz = $(pkg_deb_dir)/$(package)_$(version).orig.tar.gz
pkg_deb_src = $(pkg_deb_dir)/$(package)_$(version)-$(revision)_source.changes
pkg_deb_bin = $(pkg_deb_dir)/$(package)_$(version)-$(revision)_$(architecture).changes

deb_pkg_key = CB8C5858

debclean:
	rm -rf $(pkg_deb_dir)

deb: debsrc debbin

debbin: $(unpack_dir)
	cd $(unpack_dir) && dpkg-buildpackage -b -k$(deb_pkg_key)

debsrc: $(unpack_dir)
	cd $(unpack_dir) && dpkg-buildpackage -S -k$(deb_pkg_key)

$(unpack_dir): $(orig_tar_gz)
	tar -zxf $(orig_tar_gz) -C $(pkg_deb_dir)

$(pkg_deb_dir):
	mkdir $(pkg_deb_dir)

$(pkg_deb_dir)/$(tar_gz): $(pkg_deb_dir)
	git archive --format=tar.gz --prefix=$(package)-$(version) -o $(pkg_deb_dir)/$(tar_gz) HEAD

$(orig_tar_gz): $(pkg_deb_dir)/$(tar_gz)
	ln -s $(tar_gz) $(orig_tar_gz)

