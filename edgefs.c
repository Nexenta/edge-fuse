/*
 * HTTPFS: import a file from a web server to local file system
 * the main use is, to mount an iso on a web server with loop device
 *
 * depends on:
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
 *
 * This program can be distributed under the terms of the GNU GPL.
 *
 */

/*
 * (c) 2006  hmb  marionraven at users.sourceforge.net
 *
 */

/*
 * Modified to work with fuse 2.7.
 * Added keepalive
 * The passthru functionality removed to simplify the code.
 * (c) 2008-2012,2016 Michal Suchanek <hramrach@gmail.com>
 *
 */

/*
 * Modified to work with Edge-X API 1.0
 * Nexenta Systems, Inc 2017
 */

#define FUSE_USE_VERSION 26

#define _GNU_SOURCE
#define __USE_GNU

#include <fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <stdarg.h>
#include <assert.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/dir.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>
#include <stddef.h>
#include <inttypes.h>
#include <linux/tcp.h>
#include <search.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <pthread.h>
#define FUSE_LOOP fuse_session_loop_mt

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

/*
 * ECONNRESET happens with some dodgy servers so may need to handle that.
 * Allow for building without ECONNRESET in case it is not defined.
 */
#ifdef ECONNRESET
#define RETRY_ON_RESET
#endif

#define TIMEOUT 30
#define CONSOLE "/dev/console"
#define HEADER_SIZE 4096
#define MAX_REQUEST (32*1024)
#define MAX_REDIRECTS 32
#define TNAME_LEN 13
#define RESET_RETRIES 8
#define VERSION "1.0.0 \"Edge-X API client\""
#define BUCKET_MAX 1000000

enum sock_state {
	SOCK_CLOSED,
	SOCK_OPEN,
	SOCK_KEEPALIVE,
};

enum url_flags {
	URL_DUP,
	URL_SAVE,
	URL_DROP,
};

typedef struct url {
	int proto;
	long timeout;
	char *url;
	char *host; /*hostname*/
	int port;
	char *path; /*get path*/
	char *name; /*file name*/
#ifdef USE_AUTH
	char *auth; /*encoded auth data*/
#endif
#ifdef RETRY_ON_RESET
	long retry_reset; /*retry reset connections*/
	long resets;
#endif
	int sockfd;
	enum sock_state sock_type;
	int truncate;
	int redirected;
	int redirect_followed;
	int redirect_depth;
	long log_level;
	unsigned md5;
	unsigned md2;
	int ssl_initialized;
	int ssl_connected;
	gnutls_certificate_credentials_t sc;
	gnutls_session_t ss;
	const char *cafile;
	char *req_buf;
	size_t req_buf_size;
	off_t file_size;
	time_t last_modified;
	char tname[TNAME_LEN + 1];
	char *sid;
	pthread_mutex_t sid_mutex;
} struct_url;

static struct_url main_url;
static char* argv0;

/* this only works on 64-bit platforms */
#define INODE_TO_URL(_ino) ((struct_url*)(_ino))
#define URL_TO_INODE(_u) ((uint64_t)(_u))

struct dirbuf {
	char *p;
	size_t size;
};

static off_t get_stat(struct_url*, struct stat * stbuf);
static ssize_t get_data(struct_url*, off_t start, size_t size, char *dest);
static ssize_t post_data(struct_url *url, const char *data, off_t start, size_t size);
static ssize_t list_data(struct_url *url, off_t off, size_t size,
    fuse_req_t req, struct dirbuf *b);
static int del_data(struct_url *url);
static int open_client_socket(struct_url *url);
static int close_client_socket(struct_url *url);
static int close_client_force(struct_url *url);
static void destroy_url_copy(void *);

/* Protocol symbols. */
#define PROTO_HTTP 0
#define PROTO_HTTPS 1

static void
http_report(const char *reason, const char *method,
    const char *buf, size_t len)
{
	fprintf(stderr, "HTTP %s: %s\n", method, reason);
	fwrite(buf, len, 1, stderr);
	if (len && ( *(buf+len-1) != '\n')) fputc('\n', stderr);
}

static void
trace_a(const char *fmt, ...)
{
	va_list ap;
	char msg[2048];
	struct timeval tp;
	long pid = getpid();
	long thrid = syscall(SYS_gettid);
	time_t meow = time(NULL);
	char buf[64];
	struct tm tm;

	gettimeofday(&tp, 0);

	strftime(buf, sizeof (buf), "%Y-%m-%d %H:%M:%S", localtime_r(&meow, &tm));

	va_start(ap, fmt);
	vsnprintf(msg, sizeof (msg), fmt, ap);
	fprintf(stderr, "[%lu.%lu] %c, %s.%03d : %s", pid, thrid,
	    'T', buf, (int)(tp.tv_usec/1000), msg);
	va_end(ap);
}
#define trace(fmt, ...) do { \
	while (0) { fprintf(NULL, fmt, ##__VA_ARGS__); } \
	if (main_url.log_level) { \
		trace_a("%14s:%-4d : " fmt, __FILE__, __LINE__, \
			##__VA_ARGS__); \
	} \
} while (0)

#ifdef USE_AUTH

static char b64_encode_table[64] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',  /* 0-7 */
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',  /* 8-15 */
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',  /* 16-23 */
	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',  /* 24-31 */
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',  /* 32-39 */
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v',  /* 40-47 */
	'w', 'x', 'y', 'z', '0', '1', '2', '3',  /* 48-55 */
	'4', '5', '6', '7', '8', '9', '+', '/'   /* 56-63 */
};

/* Do base-64 encoding on a hunk of bytes.   Return pointer to the
 ** bytes generated.  Base-64 encoding takes up 4/3 the space of the original,
 ** plus a bit for end-padding.  3/2+5 gives a safe margin.
 */
static char *b64_encode(unsigned const char* ptr, long len) {
	char *space;
	int ptr_idx;
	int c = 0;
	int d = 0;
	int space_idx = 0;
	int phase = 0;

	/*FIXME calculate the occupied space properly*/
	size_t size = ((size_t)len * 3) /2 + 5;
	space = malloc(size+1);
	space[size] = 0;

	for (ptr_idx = 0; ptr_idx < len; ++ptr_idx) {
		switch (phase++) {
		case 0:
			c = ptr[ptr_idx] >> 2;
			d = (ptr[ptr_idx] & 0x3) << 4;
			break;
		case 1:
			c = d | (ptr[ptr_idx] >> 4);
			d = (ptr[ptr_idx] & 0xf) << 2;
			break;
		case 2:
			c = d | (ptr[ptr_idx] >> 6);
			if (space_idx < size) space[space_idx++] = b64_encode_table[c];
			c = ptr[ptr_idx] & 0x3f;
			break;
		}
		space[space_idx++] = b64_encode_table[c];
		if (space_idx == size) return space;
		phase %= 3;
	}
	if (phase != 0) {
		space[space_idx++] = b64_encode_table[d];
		if (space_idx == size) return space;
		/* Pad with ='s. */
		while (phase++ > 0) {
			space[space_idx++] = '=';
			if (space_idx == size) return space;
			phase %= 3;
		}
	}
	return space;
}

#endif /* USE_AUTH */

pthread_mutex_t tab_mutex;
struct hsearch_data tab = {0};

void hadd(struct hsearch_data *tab, char *key, fuse_ino_t ino)
{
	ENTRY item = {key, (void *)ino};
	ENTRY *pitem = &item;

	pthread_mutex_lock(&tab_mutex);
	if (hsearch_r(item, ENTER, &pitem, tab)) {
		pitem->data = (void *) ino;
	}
	pthread_mutex_unlock(&tab_mutex);
}

void hdelete(struct hsearch_data *tab, char *key)
{
	ENTRY item = {key};
	ENTRY *pitem = &item;

	pthread_mutex_lock(&tab_mutex);
	if (hsearch_r(item, FIND, &pitem, tab)) {
		pitem->data = (void *) NULL;
	}
	pthread_mutex_unlock(&tab_mutex);
}

fuse_ino_t hfind(struct hsearch_data *tab, char *key)
{
	ENTRY item = {key};
	ENTRY *pitem = &item;

	pthread_mutex_lock(&tab_mutex);
	if (hsearch_r(item, FIND, &pitem, tab)) {
		pthread_mutex_unlock(&tab_mutex);
		return (fuse_ino_t) pitem->data;
	}
	pthread_mutex_unlock(&tab_mutex);
	return (fuse_ino_t)NULL;
}

static struct_url * create_url_copy(const struct_url * url, char *newname)
{
	struct_url * res = calloc(1, sizeof(struct_url));
	memcpy(res, url, sizeof(struct_url));
	if (url->name)
		res->name = strdup(url->name);
	if (url->host)
		res->host = strdup(url->host);
	if (url->path)
		res->path = strdup(url->path);
	if (url->sid && newname && strcmp(newname, url->name) == 0)
		res->sid = strdup(url->sid);
#ifdef USE_AUTH
	if (url->auth)
		res->auth = strdup(url->auth);
#endif
	memset(res->tname, 0, TNAME_LEN + 1);
	snprintf(res->tname, TNAME_LEN, "%0*lX", TNAME_LEN, pthread_self());
	pthread_mutex_init((pthread_mutex_t *)&url->sid_mutex, NULL);
	return res;
}

fuse_ino_t newino(char *name)
{
	fuse_ino_t ino;

	ino = hfind(&tab, name);
	if (ino)
		return ino;

	struct_url *res = create_url_copy(&main_url, name);
	if (res->name)
		free(res->name);
	res->name = strdup(name);
	ino = URL_TO_INODE(res);
	hadd(&tab, name, ino);
	return ino;
}

/*
 * The FUSE operations originally ripped from the hello_ll sample.
 */

static int edgefs_stat(fuse_ino_t ino, struct fuse_file_info *fi,
    struct stat *stbuf)
{
	int res;

	trace("ino=%lx\n", ino);
	stbuf->st_ino = ino;

	if (ino == 1) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		return 0;
	}

	struct_url *url = fi ?
		(struct_url *)fi->fh : create_url_copy(INODE_TO_URL(ino), NULL);

	stbuf->st_mode = S_IFREG | 0644;
	stbuf->st_nlink = 1;

	res = (get_stat(url, stbuf) == -1) ? -1 : 0;
	if (!fi)
		destroy_url_copy(url);
	return res;
}

static void edgefs_getattr(fuse_req_t req, fuse_ino_t ino,
    struct fuse_file_info *fi)
{
	struct stat stbuf;

	(void) fi;

	trace("getattr ino=%lx\n", ino);
	memset(&stbuf, 0, sizeof(stbuf));
	if (edgefs_stat(ino, fi, &stbuf) < 0)
		assert(errno),fuse_reply_err(req, errno);
	else
		fuse_reply_attr(req, &stbuf, 1.0);
}

static void edgefs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct fuse_entry_param e;
	memset(&e, 0, sizeof(e));
	e.attr_timeout = 1.0;
	e.entry_timeout = 1.0;

	trace("lookup %s\n", name);
	if (parent != 1) {
		e.ino = 0;
	} else {
		e.ino = newino((char*)name);
		if (edgefs_stat(e.ino, NULL, &e.attr) < 0) {
			assert(errno);
			fuse_reply_err(req, errno);
			return;
		}

	}
	fuse_reply_entry(req, &e);
}

static void dirbuf_add(fuse_req_t req, struct dirbuf *b, const char *name,
    fuse_ino_t ino)
{
	struct stat stbuf;
	size_t oldsize = b->size;
	b->size += fuse_add_direntry(req, NULL, 0, name, NULL, 0);
	b->p = (char *) realloc(b->p, b->size);
	memset(&stbuf, 0, sizeof(stbuf));
	stbuf.st_ino = ino;
	fuse_add_direntry(req, b->p + oldsize, b->size - oldsize, name, &stbuf,
	    (off_t) b->size);
}

#define min(x, y) ((x) < (y) ? (x) : (y))

static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize,
    off_t off, size_t maxsize)
{
	assert(off >= 0);

	if (off < bufsize)
		return fuse_reply_buf(req, buf + off,
		    min(bufsize - (size_t)off, maxsize));
	else
		return fuse_reply_buf(req, NULL, 0);
}

static void edgefs_readdir(fuse_req_t req, fuse_ino_t dir_ino, size_t size,
    off_t off, struct fuse_file_info *fi)
{
	(void) fi;
	struct dirbuf b;
	ssize_t res;

	trace("readdir ino=%lx\n", dir_ino);
	if (dir_ino != 1) {
		fuse_reply_err(req, ENOTDIR);
		return;
	}

	struct_url *url = create_url_copy(&main_url, NULL);

	if (url->req_buf
	    && ( (url->req_buf_size < size)
		    || ( (url->req_buf_size > size)
			    && (url->req_buf_size > MAX_REQUEST)))) {
		free(url->req_buf);
		url->req_buf = 0;
	}
	if (!url->req_buf) {
		url->req_buf_size = size;
		url->req_buf = malloc(size);
	}

	memset(&b, 0, sizeof(b));
	dirbuf_add(req, &b, ".", 1);
	dirbuf_add(req, &b, "..", 1);

	if ((res = list_data(url, off, size, req, &b)) < 0) {
		free(b.p);
		fuse_reply_err(req, EIO);
		return;
	}

	reply_buf_limited(req, b.p, b.size, off, size);
	free(b.p);
	destroy_url_copy(url);
}

static void edgefs_open(fuse_req_t req, fuse_ino_t ino,
    struct fuse_file_info *fi)
{
	trace("open %lx\n", ino);
	if (ino == 1)
		fuse_reply_err(req, EISDIR);
	else {
		struct_url *url = create_url_copy(INODE_TO_URL(ino), NULL);
		int fd = open_client_socket(url);
		if (fd < 0) {
			destroy_url_copy(url);
			fuse_reply_err(req, EIO);
			return;
		}
		url->sock_type = SOCK_KEEPALIVE;
		fi->fh = (uint64_t)url;
		if (fi->flags & O_TRUNC)
			url->truncate = 1;
		fuse_reply_open(req, fi);
	}
}

static void edgefs_read(fuse_req_t req, fuse_ino_t ino, size_t size,
    off_t off, struct fuse_file_info *fi)
{
	(void) fi;

	trace("read ino=%lx\n", ino);
	struct_url *url = (struct_url *)fi->fh;
	ssize_t res;

	if (url->file_size == off) {
		/* Handling of EOF is not well documented, returning EOF as error
		 * does not work but this does.  */
		fuse_reply_buf(req, NULL,  0);
		return;
	}

	char *out_buf = malloc(size);
	if ((res = get_data(url, off, size, out_buf)) < 0) {
		assert(errno);
		fuse_reply_err(req, errno);
	} else {
		fuse_reply_buf(req, out_buf, (size_t)res);
	}
	free(out_buf);
}

static void edgefs_write(fuse_req_t req, fuse_ino_t ino,
    const char *data, size_t size, off_t off, struct fuse_file_info *fi)
{
	(void) fi;

	trace("write ino=%lx\n", ino);
	struct_url *url = (struct_url *)fi->fh;
	ssize_t res;

	res = post_data(url, data, off, size);
	if (res < 0)
		fuse_reply_err(req, EIO);
	else
		fuse_reply_write(req, (size_t)res);
}

static void edgefs_flush(fuse_req_t req, fuse_ino_t ino,
    struct fuse_file_info *fi)
{
	(void) fi;

	trace("flush ino=%lx\n", ino);
	struct_url *url = (struct_url *)fi->fh;
	ssize_t res;

	res = post_data(url, NULL, 0, 0);
	if (res < 0)
		fuse_reply_err(req, EIO);
	else
		fuse_reply_err(req, 0);
}

static void edgefs_release(fuse_req_t req, fuse_ino_t ino,
    struct fuse_file_info *fi)
{
	(void) fi;

	trace("release ino=%lx\n", ino);
	struct_url *url = (struct_url *)fi->fh;
	ssize_t res;

	res = post_data(url, NULL, 0, 0);
	if (res < 0)
		fuse_reply_err(req, errno);
	else
		fuse_reply_err(req, 0);
	destroy_url_copy(url);
}

static void edgefs_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
    struct fuse_file_info *fi)
{
	(void) fi;

	trace("fsync ino=%lx\n", ino);
	struct_url *url = (struct_url *)fi->fh;
	ssize_t res;

	res = post_data(url, NULL, 0, 0);
	if (res < 0)
		fuse_reply_err(req, errno);
	else
		fuse_reply_err(req, 0);
}

static void edgefs_create(fuse_req_t req, fuse_ino_t parent, const char *name,
    mode_t mode, struct fuse_file_info *fi)
{
	ssize_t res;
	struct fuse_entry_param e;
	memset(&e, 0, sizeof(e));

	trace("create parent %ld name %s\n", parent, name);
	struct stat st;
	memset(&st, 0, sizeof(st));

	e.ino = newino((char*)name);

	struct_url *url = create_url_copy(INODE_TO_URL(e.ino), NULL);
	int fd = open_client_socket(url);
	if (fd < 0) {
		destroy_url_copy(url);
		fuse_reply_err(req, EIO);
		return;
	}
	url->sock_type = SOCK_KEEPALIVE;
	fi->fh = (uint64_t)url;

	url->truncate = 1;
	res = post_data(url, NULL, 0, 0);
	if (res < 0) {
		fuse_reply_err(req, errno);
		return;
	}
	st.st_mode = S_IFREG | 0644;
	st.st_nlink = 1;
	st.st_mtime = url->last_modified;
	st.st_size = url->file_size;
	e.attr = st;
	fuse_reply_create(req, &e, fi);
}

static void edgefs_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
    int to_set, struct fuse_file_info *fi)
{
	struct stat stbuf;

	(void) fi;

	trace("setattr ino=%lx\n", ino);
	memset(&stbuf, 0, sizeof(stbuf));
	if (edgefs_stat(ino, fi, &stbuf) < 0)
		assert(errno),fuse_reply_err(req, errno);
	else
		fuse_reply_attr(req, &stbuf, 1.0);
}

static void edgefs_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	fuse_ino_t ino;
	trace("unlink %s\n", name);

	ino = hfind(&tab, (char*)name);
	if (!ino) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	struct_url *url = create_url_copy(INODE_TO_URL(ino), NULL);
	del_data(url);
	fuse_reply_err(req, 0);
}

static void edgefs_forget(fuse_req_t req, fuse_ino_t ino, unsigned long nlookup)
{
	trace("forget ino=%lx %s\n", ino, INODE_TO_URL(ino)->name);
	fuse_reply_none(req);
}

static void edgefs_init(void *userdata, struct fuse_conn_info *conn)
{
	conn->max_write = 131072;
	conn->max_readahead = 131072;
}

static struct fuse_lowlevel_ops edgefs_oper = {
	.init               = edgefs_init,
	.lookup             = edgefs_lookup,
	.getattr            = edgefs_getattr,
	.setattr            = edgefs_setattr,
	.readdir            = edgefs_readdir,
	.open               = edgefs_open,
	.read               = edgefs_read,
	.write              = edgefs_write,
//	.flush              = edgefs_flush,
	.release            = edgefs_release,
	.forget             = edgefs_forget,
	.fsync              = edgefs_fsync,
	.create             = edgefs_create,
	.unlink             = edgefs_unlink,
};

/*
 * A few utility functions
 */
#ifdef NEED_STRNDUP
static char *strndup(const char *str, size_t n) {
	if (n > strlen(str)) n = strlen(str);
	char *res = malloc(n + 1);
	memcpy(res, str, n);
	res[n] = 0;
	return res;
}
#endif

static int mempref(const char *mem, const char *pref, size_t size, int case_sensitive)
{
	/* return true if found */
	if (size < strlen(pref)) return 0;
	if (case_sensitive)
		return ! memcmp(mem, pref, strlen(pref));
	else {
		int i;
		for (i = 0; i < strlen(pref); i++)
			/* Unless somebody calling setlocale() behind our back locale should be C.  */
			/* It is important to not uppercase in languages like Turkish.  */
			if (tolower(mem[i]) != tolower(pref[i]))
				return 0;
		return 1;
	}
}

static void errno_report(const char *where);
static void ssl_error(ssize_t error, struct_url * url, const char *where);
static void ssl_error_p(ssize_t error, struct_url * url, const char *where, const char *extra);
/* Functions to deal with gnutls_datum_t stolen from gnutls docs.
 * The structure does not seem documented otherwise.
 */
static gnutls_datum_t
load_file (const char *file)
{
	FILE *f;
	gnutls_datum_t loaded_file = { NULL, 0 };
	long filelen;
	void *ptr;
	f = fopen (file, "r");
	if (!f)
		errno_report(file);
	else if (fseek (f, 0, SEEK_END) != 0)
		errno_report(file);
	else if ((filelen = ftell (f)) < 0)
		errno_report(file);
	else if (fseek (f, 0, SEEK_SET) != 0)
		errno_report(file);
	else if (!(ptr = malloc ((size_t) filelen)))
		errno_report(file);
	else if (fread (ptr, 1, (size_t) filelen, f) < (size_t) filelen)
		errno_report(file);
	else {
		loaded_file.data = ptr;
		loaded_file.size = (unsigned int) filelen;
		trace("Loaded '%s' %ld bytes\n", file, filelen);
		/* fwrite(ptr, filelen, 1, stderr); */
	}
	return loaded_file;
}

static void
unload_file (gnutls_datum_t data)
{
	free (data.data);
}

/* This function will print some details of the
 * given session.
 *
 * Stolen from the GNUTLS docs.
 */
int
print_ssl_info (gnutls_session_t session)
{
	const char *tmp;
	gnutls_credentials_type_t cred;
	gnutls_kx_algorithm_t kx;
	int dhe, ecdh;
	dhe = ecdh = 0;
	if (!session) {
		trace("No SSL session data.\n");
		return 0;
	}
	/* print the key exchange’s algorithm name
	 */
	kx = gnutls_kx_get (session);
	tmp = gnutls_kx_get_name (kx);
	trace("- Key Exchange: %s\n", tmp);
	/* Check the authentication type used and switch
	 * to the appropriate.
	 */
	cred = gnutls_auth_get_type (session);
	switch (cred)
	{
	case GNUTLS_CRD_CERTIFICATE:
		/* certificate authentication */
		/* Check if we have been using ephemeral Diffie-Hellman.
		 */
		if (kx == GNUTLS_KX_DHE_RSA || kx == GNUTLS_KX_DHE_DSS)
			dhe = 1;
#if (GNUTLS_VERSION_MAJOR > 3)
		else if (kx == GNUTLS_KX_ECDHE_RSA || kx == GNUTLS_KX_ECDHE_ECDSA)
			ecdh = 1;
#endif
		/* cert should have been printed when it was verified */
		break;
	default:
		trace("Not a x509 sesssion !?!\n");

	}
#if (GNUTLS_VERSION_MAJOR > 3)
	/* switch */
	if (ecdh != 0)
		trace("- Ephemeral ECDH using curve %s\n",
		    gnutls_ecc_curve_get_name (gnutls_ecc_curve_get (session)));
	else
#endif
		if (dhe != 0)
			trace("- Ephemeral DH using prime of %d bits\n",
			    gnutls_dh_get_prime_bits (session));
	/* print the protocol’s name (ie TLS 1.0)
	 */
	tmp = gnutls_protocol_get_name (gnutls_protocol_get_version (session));
	trace("- Protocol: %s\n", tmp);
	/* print the certificate type of the peer.
	 * ie X.509
	 */
	tmp =
		gnutls_certificate_type_get_name (gnutls_certificate_type_get (session));
	trace("- Certificate Type: %s\n", tmp);
	/* print the compression algorithm (if any)
	 */
	tmp = gnutls_compression_get_name (gnutls_compression_get (session));
	trace("- Compression: %s\n", tmp);
	/* print the name of the cipher used.
	 * ie 3DES.
	 */
	tmp = gnutls_cipher_get_name (gnutls_cipher_get (session));
	trace("- Cipher: %s\n", tmp);
	/* Print the MAC algorithms name.
	 * ie SHA1
	 */
	tmp = gnutls_mac_get_name (gnutls_mac_get (session));
	trace("- MAC: %s\n", tmp);
	trace("Note: SSL paramaters may change as new connections are established to the server.\n");
	return 0;
}



/* This function will try to verify the peer’s certificate, and
 * also check if the hostname matches, and the activation, expiration dates.
 *
 * Stolen from the gnutls manual.
 */
static int
verify_certificate_callback (gnutls_session_t session)
{
	unsigned int status;
	const gnutls_datum_t *cert_list;
	unsigned int cert_list_size;
	int ret;
	gnutls_x509_crt_t cert;
	gnutls_datum_t data = {0};
	struct_url * url = gnutls_session_get_ptr (session);
	const char *hostname = url->host;

	/* This verification function uses the trusted CAs in the credentials
	 * structure. So you must have installed one or more CA certificates.
	 */
	ret = gnutls_certificate_verify_peers2 (session, &status);
	if (ret < 0)
	{
		ssl_error(ret, url, "verify certificate");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}
	if (status & GNUTLS_CERT_INVALID)
		trace("The server certificate is NOT trusted.\n");
	if (status & GNUTLS_CERT_INSECURE_ALGORITHM)
		trace("The server certificate uses an insecure algorithm.\n");
	if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
		trace("The server certificate hasn’t got a known issuer.\n");
	if (status & GNUTLS_CERT_REVOKED)
		trace("The server certificate has been revoked.\n");
	if (status & GNUTLS_CERT_EXPIRED)
		trace("The server certificate has expired\n");
	if (status & GNUTLS_CERT_NOT_ACTIVATED)
		trace("The server certificate is not yet activated\n");
	/* Up to here the process is the same for X.509 certificates and
	 * OpenPGP keys. From now on X.509 certificates are assumed. This can
	 * be easily extended to work with openpgp keys as well.
	 */
	if (gnutls_certificate_type_get (session) != GNUTLS_CRT_X509)
		return GNUTLS_E_CERTIFICATE_ERROR;
	if (gnutls_x509_crt_init (&cert) < 0)
	{
		ssl_error(ret, url, "verify certificate");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}
	cert_list = gnutls_certificate_get_peers (session, &cert_list_size);
	if (cert_list == NULL)
	{
		fprintf(stderr, "No server certificate was found!\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}
	/* Check the hostname matches the certificate. */
	ret = gnutls_x509_crt_import (cert, &cert_list[0], GNUTLS_X509_FMT_DER);
	if (ret < 0)
	{
		ssl_error(ret, url, "parsing certificate");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}
	if (!(url->ssl_connected)) if (!gnutls_x509_crt_print (cert, GNUTLS_CRT_PRINT_FULL, &data)) {
		trace("%s", data.data);
		gnutls_free(data.data);
	}
	if (!hostname || !gnutls_x509_crt_check_hostname (cert, hostname))
	{
		int found = 0;
		if (hostname) {
			int i;
			size_t len = strlen(hostname);
			if (*(hostname+len-1) == '.') len--;
			if (!(url->ssl_connected)) trace("Server hostname verification failed. Trying to peek into the cert.\n");
			for (i=0;;i++) {
				char *dn = NULL;
				size_t dn_size = 0;
				int dn_ret = 0;
				int match=0;
				gnutls_x509_crt_get_dn_by_oid(cert, GNUTLS_OID_X520_COMMON_NAME, i, 0, dn, &dn_size);
				if (dn_size) dn = malloc(dn_size + 1); /* nul not counted */
				if (dn)
					dn_ret = gnutls_x509_crt_get_dn_by_oid(cert, GNUTLS_OID_X520_COMMON_NAME, i, 0, dn, &dn_size);
				if (!dn_ret) {
					if (dn) {
						if (*(dn+dn_size-1) == '.') dn_size--;
						if (len == dn_size)
							match = ! strncmp(dn, hostname, len);
						if (match) found = 1;
						if (!(url->ssl_connected)) trace("Cert CN(%i): %s: %c\n", i, dn, match?'*':'X');
					}}
				else
					ssl_error(dn_ret, url, "getting cert subject data");
				if (dn) free(dn);
				if (dn_ret || !dn)
					break;
			}
		}
		if (!found) {
			trace("The server certificate’s owner does not match hostname ’%s’\n",
			    hostname);
			return GNUTLS_E_CERTIFICATE_ERROR;
		}
	}
	gnutls_x509_crt_deinit (cert);
	/*
	 * It the status includes GNUTLS_CERT_INVALID whenever
	 * there is a problem and the other flags are just informative.
	 */
	if (status & GNUTLS_CERT_INVALID)
		return GNUTLS_E_CERTIFICATE_ERROR;
	/* notify gnutls to continue handshake normally */
	return 0;
}


static void logfunc(int level, const char *str)
{
	fputs(str, stderr);
}

static void ssl_error_p(ssize_t error, struct_url * url, const char *where, const char *extra)
{
	const char *err_desc;
	if ((error == GNUTLS_E_FATAL_ALERT_RECEIVED) || (error == GNUTLS_E_WARNING_ALERT_RECEIVED))
		err_desc = gnutls_alert_get_name(gnutls_alert_get(url->ss));
	else
		err_desc = gnutls_strerror((int)error);

	fprintf(stderr, "SSL: %s: %s: %s%zd %s.\n", url->tname, where, extra, error, err_desc);
}

static void ssl_error(ssize_t error, struct_url * url, const char *where)
{
	ssl_error_p(error, url, where, "");
	/* FIXME try to decode errors more meaningfully */
	errno = EIO;
}

static void errno_report(const char *where)
{
	int e = errno;
	fprintf(stderr, "Error: %s: %d %s.\n", where, errno, strerror(errno));
	errno = e;
}

static char *url_encode(char *path) {
	return strdup(path); /*FIXME encode*/
}

/*
 * functions for handling struct_url
 */

static int init_url(struct_url* url)
{
	memset(url, 0, sizeof(*url));
	url->sock_type = SOCK_CLOSED;
	url->timeout = TIMEOUT;
#ifdef RETRY_ON_RESET
	url->retry_reset = RESET_RETRIES;
#endif
	url->cafile = CERT_STORE;
	return 0;
}

static int free_url(struct_url* url)
{
	if (url->sock_type != SOCK_CLOSED)
		close_client_force(url);
	if (url->host) free(url->host);
	url->host = 0;
	if (url->path) free(url->path);
	url->path = 0;
	if (url->name) free(url->name);
	url->name = 0;
#ifdef USE_AUTH
	if (url->auth) free(url->auth);
	url->auth = 0;
#endif
	pthread_mutex_destroy(&url->sid_mutex);
	url->port = 0;
	url->proto = 0; /* only after socket closed */
	url->file_size=0;
	url->last_modified=0;
	return 0;
}

static void print_url(FILE *f, const struct_url * url)
{
	char *protocol = "?!?";
	switch(url->proto) {
	case PROTO_HTTP:
		protocol = "http";
		break;;
	case PROTO_HTTPS:
		protocol = "https";
		break;;
	}
	fprintf(f, "host name: \t%s\n", url->host);
	fprintf(f, "port number: \t%d\n", url->port);
	fprintf(f, "protocol: \t%s\n", protocol);
	fprintf(f, "request path: \t%s\n", url->path);
#ifdef USE_AUTH
	fprintf(f, "auth data: \t%s\n", url->auth ? "(present)" : "(null)");
#endif
}

static int parse_url(char *_url, struct_url* res, enum url_flags flag)
{
	const char *url_orig;
	const char *url;
	const char *http = "http://";
	const char *https = "https://";
	int path_start = '/';

	if (!_url)
		_url = res->url;
	assert(_url);
	switch(flag) {
	case URL_DUP:
		_url = strdup(_url);
	case URL_SAVE:
		assert (_url != res->url);
		if (res->url)
			free(res->url);
		res->url = _url;
		break;
	case URL_DROP:
		assert (res->url);
		break;
	}
	/* constify so compiler warns about modification */
	url_orig = url = _url;

	close_client_force(res);
	res->ssl_connected = 0;

	if (strncmp(http, url, strlen(http)) == 0) {
		url += strlen(http);
		res->proto = PROTO_HTTP;
		res->port = 80;
	} else if (strncmp(https, url, strlen(https)) == 0) {
		url += strlen(https);
		res->proto = PROTO_HTTPS;
		res->port = 443;
	} else {
		fprintf(stderr, "Invalid protocol in url: %s\n", url_orig);
		return -1;
	}

	/* determine if path was given */
	if (res->path)
		free(res->path);
	if (strchr(url, path_start))
		res->path = url_encode(strchr(url, path_start));
	else {
		path_start = 0;
		res->path = strdup("/");
	}


#ifdef USE_AUTH
	/* Get user and password */
	if (res->auth)
		free(res->auth);
	if (strchr(url, '@') && (strchr(url, '@') < strchr(url, path_start))) {
		res->auth = b64_encode((unsigned char *)url, strchr(url, '@') - url);
		url = strchr(url, '@') + 1;
	} else {
		res->auth = 0;
	}
#endif /* USE_AUTH */

	/* Get port number. */
	int host_end = path_start;
	if (strchr(url, ':') && (strchr(url, ':') < strchr(url, path_start))) {
		/* FIXME check that port is a valid numeric value */
		res->port = atoi(strchr(url, ':') + 1);
		if (!res->port) {
			fprintf(stderr, "Invalid port in url: %s\n", url_orig);
			return -1;
		}
		host_end = ':';
	}
	/* Get the host name. */
	if (url == strchr(url, host_end)) { /*no hastname in the url */
		fprintf(stderr, "No hostname in url: %s\n", url_orig);
		return -1;
	}
	if (res->host)
		free(res->host);
	res->host = strndup(url, (size_t)(strchr(url, host_end) - url));

#if 0
	if (flag != URL_DROP) {
		/* Get the file name. */
		url = strchr(url, path_start);
		const char *end = url + strlen(url);
		end--;

		/* Handle broken urls with multiple slashes. */
		while((end > url) && (*end == '/')) end--;
		end++;
		if (res->name)
			free(res->name);
		if ((path_start == 0) || (end == url)
		    || (strncmp(url, "/", (size_t)(end - url)) ==  0)) {
			res->name = strdup(res->host);
		} else {
			while(strchr(url, '/') && (strchr(url, '/') < end))
				url = strchr(url, '/') + 1;
			res->name = strndup(url, (size_t)(end - url));
		}
	} else
		assert(res->name);
#endif
	res->name = strdup("");

	return res->proto;
}

static void usage(void)
{
	fprintf(stderr, "%s >>> Version: %s <<<\n", __FILE__, VERSION);
	fprintf(stderr, "usage:  %s [-c [console]] "
	    "[-a file] [-d n] [-5] [-2] "
	    "[-f] [-t timeout] [-r n] url mount-parameters\n\n", argv0);
	fprintf(stderr, "\t -2 \tAllow RSA-MD2 server certificate\n");
	fprintf(stderr, "\t -5 \tAllow RSA-MD5 server certificate\n");
	fprintf(stderr, "\t -a \tCA file used to verify server certificate\n\t\t(default: %s)\n", CERT_STORE);
	fprintf(stderr, "\t -c \tuse console for standard input/output/error\n\t\t(default: %s)\n", CONSOLE);
	fprintf(stderr, "\t -d \tdebug level (default 0)\n");
	fprintf(stderr, "\t -f \tstay in foreground - do not fork\n");
#ifdef RETRY_ON_RESET
	fprintf(stderr, "\t -r \tnumber of times to retry connection on reset\n\t\t(default: %i)\n", RESET_RETRIES);
#endif
	fprintf(stderr, "\t -t \tset socket timeout in seconds (default: %i)\n", TIMEOUT);
	fprintf(stderr, "\tmount-parameters should include the mount point and FUSE -o parameters\n");
}

#define shift { if (!argv[1] || !argv[2]) { usage(); return 4; };\
	argc--; argv[1] = argv[0]; argv = argv + 1;}

static int convert_num(long * num, char ** argv)
{
	char *end = " ";
	if (isdigit(*(argv[1]))) {
		*num = strtol(argv[1], &end, 0);
		/* now end should point to '\0' */
	}
	if (*end) {
		usage();
		fprintf(stderr, "'%s' is not a number.\n",
		    argv[1]);
		return -1;
	}
	return 0;
}



int main(int argc, char *argv[])
{
	char *fork_terminal = CONSOLE;
	int do_fork = 1;
	putenv("TZ=");/*UTC*/
	argv0 = argv[0];
	init_url(&main_url);
	strncpy(main_url.tname, "main", TNAME_LEN);

	while( argv[1] && (*(argv[1]) == '-'))
	{
		char *arg = argv[1]; shift;
		while (*++arg) {
			switch (*arg) {
			case 'c': if (*(argv[1]) != '-') {
					  fork_terminal = argv[1]; shift;
				  } else {
					  fork_terminal = 0;
				  }
				  break;
			case '2': main_url.md2 = GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD2;
				  break;
			case '5': main_url.md5 = GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD5;
				  break;
			case 'a': main_url.cafile = argv[1];
				  shift;
				  break;
			case 'd': if (convert_num(&main_url.log_level, argv))
					  return 4;
				  shift;
				  break;
#ifdef RETRY_ON_RESET
			case 'r': if (convert_num(&main_url.retry_reset, argv))
					  return 4;
				  shift;
				  break;
#endif
			case 't': if (convert_num(&main_url.timeout, argv))
					  return 4;
				  shift;
				  break;
			case 'f': do_fork = 0;
				  break;
			default:
				  usage();
				  fprintf(stderr, "Unknown option '%c'.\n", *arg);
				  return 4;
			}
		}
	}

	if (argc < 3) {
		usage();
		return 1;
	}
	if (parse_url(argv[1], &main_url, URL_DUP) == -1) {
		fprintf(stderr, "invalid url: %s\n", argv[1]);
		return 2;
	}
	print_url(stderr, &main_url);
	int sockfd = open_client_socket(&main_url);
	if (sockfd < 0) {
		fprintf(stderr, "Connection failed.\n");
		return 3;
	}
	else {
		print_ssl_info(main_url.ss);
	}
	close_client_socket(&main_url);
	struct stat st;
	off_t size = get_stat(&main_url, &st);
	if (size >= 0) {
		trace("file size: \t%" PRIdMAX "\n", (intmax_t)size);
	} else {
		return 3;
	}

	pthread_mutex_init(&tab_mutex, NULL);
	hcreate_r(BUCKET_MAX, &tab);

	shift;
	if (fork_terminal && access(fork_terminal, O_RDWR)) {
		errno_report(fork_terminal);
		fork_terminal=0;
	}

	close_client_force(&main_url); /* each thread should open its own socket */

	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_chan *ch;
	char *mountpoint;
	int err = -1;
	int fork_res = 0;

	if (fuse_parse_cmdline(&args, &mountpoint, NULL, NULL) != -1 &&
	    (ch = fuse_mount(mountpoint, &args)) != NULL) {

		/* try to fork at some point where the setup is mostly done */
		/* FIXME try to close std* and the like ? */
		if (do_fork) fork_res = fork();

		switch (fork_res) {
		case 0:

			{
				if (fork_terminal) {
					/* if we can access the console use it */
					int fd = open(fork_terminal, O_RDONLY);
					dup2(fd, 0);
					close (fd);
					fd = open(fork_terminal, O_WRONLY);
					dup2(fd, 1);
					close (fd);
					fd = open(fork_terminal, O_WRONLY|O_SYNC);
					dup2(fd, 2);
					close (fd);
				}

				struct fuse_session *se;
				se = fuse_lowlevel_new(&args, &edgefs_oper,
				    sizeof(edgefs_oper), NULL);
				if (se != NULL) {
					if (fuse_set_signal_handlers(se) != -1) {
						fuse_session_add_chan(se, ch);
						err = FUSE_LOOP(se);
						fuse_remove_signal_handlers(se);
						fuse_session_remove_chan(ch);
					}
					fuse_session_destroy(se);
				}
				fuse_unmount(mountpoint, ch);
			}
			break;;
		case -1:
			errno_report("fork");
			break;;
		default:
			err = 0;
			break;;
		}
	}
	fuse_opt_free_args(&args);

	return err ? err : 0;
}

/* handle non-fatal SSL errors */
int handle_ssl_error(struct_url *url, ssize_t * res, const char *where)
{
	/* do not handle success */
	if (!res)
		return 0;
	/*
	 * It is suggested to retry GNUTLS_E_INTERRUPTED and GNUTLS_E_AGAIN
	 * However, retrying only causes delay in practice. FIXME
	 */
	if ((*res == GNUTLS_E_INTERRUPTED) || (*res == GNUTLS_E_AGAIN))
		return 0;

	if (*res == GNUTLS_E_REHANDSHAKE) {
		trace("SSL %s: %s: %zd %s.\n", url->tname, where, *res,
		    "SSL rehanshake requested by server");
		if (gnutls_safe_renegotiation_status(url->ss)) {
			*res = gnutls_handshake (url->ss);
			if (*res) {
				return 0;
			}
			return 1;
		} else {
			fprintf(stderr, "SSL %s: %s: %zd %s.\n", url->tname, where, *res,
			    "safe rehandshake not supported on this connection");
			return 0;
		}
	}

	if (!gnutls_error_is_fatal((int)*res)) {
		ssl_error_p(*res, url, where, "non-fatal SSL error ");
		*res = 0;
		return 1;
	}

	return 0;
}

/*
 * Socket operations that abstract ssl and keepalive as much as possible.
 * Keepalive is set when parsing the headers.
 *
 */

static int close_client_socket(struct_url *url) {
	if (url->sock_type == SOCK_KEEPALIVE) {
		trace("%s: keeping socket open.\n", url->tname);
		return SOCK_KEEPALIVE;
	}
	return close_client_force(url);
}

static int close_client_force(struct_url *url) {
	int sock_closed = 0;

	if (url->sock_type != SOCK_CLOSED) {
		trace("%s: closing socket.\n", url->tname);
		if (url->proto == PROTO_HTTPS) {
			trace("%s: closing SSL socket.\n", url->tname);
			gnutls_bye(url->ss, GNUTLS_SHUT_RDWR);
			gnutls_deinit(url->ss);
		}
		close(url->sockfd);
		sock_closed = 1;
	}
	url->sock_type = SOCK_CLOSED;

	if (url->redirected && url->redirect_followed) {
		trace("%s: returning from redirect to master %s\n",
		    url->tname, url->url);
		if (sock_closed) url->redirect_depth = 0;
		url->redirect_followed = 0;
		url->redirected = 0;
		parse_url(NULL, url, URL_DROP);
		print_url(stderr, url);
		return -EAGAIN;
	}
	return url->sock_type;
}

static void destroy_url_copy(void * urlptr)
{
	if (urlptr) {
		free_url(urlptr);
		free(urlptr);
	}
}

static ssize_t read_client_socket(struct_url *url, void * buf, size_t len) {
	ssize_t res;
	struct timeval timeout;
	timeout.tv_sec = url->timeout;
	timeout.tv_usec = 0;
	setsockopt(url->sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	if (url->proto == PROTO_HTTPS) {
		do {
			res = gnutls_record_recv(url->ss, buf, len);
		} while ((res < 0) && handle_ssl_error(url, &res, "read"));
		if (res <= 0) ssl_error(res, url, "read");
	} else {
		res = read(url->sockfd, buf, len);
		if (res <= 0) errno_report("read");
	}
	return res;
}

static ssize_t
write_client_socket(struct_url *url, const void * buf, size_t len)
{
	do {
		int fd = open_client_socket(url);
		ssize_t res;

		if (fd < 0) return -1; /*error hopefully reported by open*/
		if (url->proto == PROTO_HTTPS) {
			do {
				res = gnutls_record_send(url->ss, buf, len);
			} while ((res < 0) && handle_ssl_error(url, &res, "write"));
			if (res <= 0) ssl_error(res, url, "write");
		} else {
			res = write(url->sockfd, buf, len);
			trace("wrote %ld bytes, sock_type keep-alive? %d\n", res,
			    url->sock_type == SOCK_KEEPALIVE);
			if (res <= 0) errno_report("write");
		}
		if (!(res <= 0) || (url->sock_type != SOCK_KEEPALIVE)) return res;

		/* retry a failed keepalive socket */
		close_client_force(url);
	} while (url->sock_type == SOCK_KEEPALIVE);
	return -1; /*should not reach*/
}

/*
 * Function yields either a positive int after connecting to
 * host 'hostname' on port 'port'  or < 0 in case of error
 *
 * It handles keepalive by not touching keepalive sockets.
 * The SSL context is created so that read/write can use it.
 *
 * hostname is something like 'www.tmtd.de' or 192.168.0.86
 * port is expected in machine order (not net order)
 *
 * ((Flonix  defines USE_IPV6))
 *
 */
#if defined(AF_INET6) && defined(IN6_IS_ADDR_V4MAPPED)
#define USE_IPV6
#endif

static int open_client_socket(struct_url *url) {
#ifdef USE_IPV6
	struct addrinfo hints;
	char portstr[10];
	int gaierr;
	struct addrinfo* ai;
	struct addrinfo* aiv4;
	struct addrinfo* aiv6 = 0;
	struct sockaddr_in6 sa;
#else /* USE_IPV6 */
	struct hostent *he;
	struct sockaddr_in sa;
#endif /* USE_IPV6 */
	socklen_t sa_len;
	int sock_family, sock_type, sock_protocol;

	if (url->sock_type == SOCK_KEEPALIVE) {
		trace("%s: reusing keepalive socket.\n", url->tname);
		return url->sock_type;
	}

	if (url->sock_type != SOCK_CLOSED) close_client_socket(url);

	if (url->redirected)
		url->redirect_followed = 1;

	trace("%s: connecting to %s port %i.\n", url->tname, url->host, url->port);

	(void) memset((void*) &sa, 0, sizeof(sa));

#ifdef USE_IPV6
	(void) memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	(void) snprintf(portstr, sizeof(portstr), "%d", (int) url->port);
	if ((gaierr = getaddrinfo(url->host, portstr, &hints, &ai)) != 0) {
		trace("%s: getaddrinfo %s - %s\n",
		    url->tname, url->host, gai_strerror(gaierr));
		errno = EIO;
		return -1;
	}

	/* Find the first IPv4 and IPv6 entries. */
	for (aiv4 = ai; aiv4 != NULL; aiv4 = aiv4->ai_next) {
		if (aiv4->ai_family == AF_INET)
			break;
		if ((aiv4->ai_family == AF_INET6) && (aiv6 == NULL))
			aiv6 = aiv4;
	}

	/* If there's an IPv4 address, use that, otherwise try IPv6. */
	if (aiv4 == NULL)
		aiv4 = aiv6;
	if (aiv4 == NULL) {
		(void) fprintf(stderr, "%s: no valid address found for host %s\n",
		    url->tname, url->host);
		errno = EIO;
		return -1;
	}
	if (sizeof(sa) < aiv4->ai_addrlen) {
		(void) fprintf(stderr, "%s: %s - sockaddr too small (%lu < %lu)\n",
		    url->tname, url->host, (unsigned long) sizeof(sa),
		    (unsigned long) aiv4->ai_addrlen);
		errno = EIO;
		return -1;
	}
	sock_family = aiv4->ai_family;
	sock_type = aiv4->ai_socktype;
	sock_protocol = aiv4->ai_protocol;
	sa_len = aiv4->ai_addrlen;
	(void) memmove(&sa, aiv4->ai_addr, sa_len);
	freeaddrinfo(ai);

#else /* USE_IPV6 */

	he = gethostbyname(url->host);
	if (he == NULL) {
		(void) fprintf(stderr, "%s: unknown host - %s\n", url->tname, url->host);
		errno = EIO;
		return -1;
	}
	sock_family = sa.sin_family = he->h_addrtype;
	sock_type = SOCK_STREAM;
	sock_protocol = 0;
	sa_len = sizeof(sa);
	(void) memmove(&sa.sin_addr, he->h_addr, he->h_length);
	sa.sin_port = htons(url->port);

#endif /* USE_IPV6 */

	url->sockfd = socket(sock_family, sock_type, sock_protocol);
	if (url->sockfd < 0) {
		errno_report("couldn't get socket");
		return -1;
	}
	int flag = 1;
	setsockopt(url->sockfd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
	if (connect(url->sockfd, (struct sockaddr*) &sa, sa_len) < 0) {
		errno_report("couldn't connect socket");
		return -1;
	}

	if ((url->proto) == PROTO_HTTPS) {
		/* Make SSL connection. */
		ssize_t r = 0;
		const char *ps = "NORMAL"; /* FIXME allow user setting */
		const char *errp = NULL;
		if (!url->ssl_initialized) {
			r = gnutls_global_init();
			if (!r)
				r = gnutls_certificate_allocate_credentials (&url->sc); /* docs suggest to share creds */
			if (url->cafile) {
				if (!r)
					r = gnutls_certificate_set_x509_trust_file (url->sc, url->cafile, GNUTLS_X509_FMT_PEM);
				if (r>0)
					trace("SSL init: loaded %zi CA certificate(s).\n", r);
				if (r>0) r = 0;
			}
			if (!r)
				gnutls_certificate_set_verify_function (url->sc, verify_certificate_callback);
			gnutls_certificate_set_verify_flags (url->sc, GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT /* suggested */
			    | url->md5 | url->md2); /* oprional for old cert compat */
			if (!r) url->ssl_initialized = 1;
			gnutls_global_set_log_level((int)url->log_level);
			gnutls_global_set_log_function(&logfunc);
		}
		if (r) {
			ssl_error(r, url, "SSL init");
			return -1;
		}

		trace("%s: initializing SSL socket.\n", url->tname);
		r = gnutls_init(&url->ss, GNUTLS_CLIENT);
		if (!r) gnutls_session_set_ptr(url->ss, url); /* used in cert verifier */
		if (!r) r = gnutls_priority_set_direct(url->ss, ps, &errp);
		if (!r) errp = NULL;
		/* alternative to gnutls_priority_set_direct: if (!r) gnutls_set_default_priority(url->ss); */
		if (!r) r = gnutls_credentials_set(url->ss, GNUTLS_CRD_CERTIFICATE, url->sc);
		if (!r) gnutls_transport_set_ptr(url->ss, (gnutls_transport_ptr_t) (intptr_t) url->sockfd);
		if (!r) r = gnutls_handshake (url->ss);
		do ; while ((r) && handle_ssl_error(url, &r, "opening SSL socket"));
		if (r) {
			close(url->sockfd);
			if (errp) fprintf(stderr, "invalid SSL priority\n %s\n %*s\n", ps, (int)(errp - ps), "^");
			fprintf(stderr, "%s:%d - ", url->host, url->port);
			ssl_error(r, url, "SSL connection failed");
			trace("%s: closing SSL socket.\n", url->tname);
			gnutls_deinit(url->ss);
			errno = EIO;
			return -1;
		}
		url->ssl_connected = 1; /* Prevent printing cert data over and over again */
	}
	trace("%s: connected to %s port %i, sockfd %d\n", url->tname, url->host, url->port, url->sockfd);
	return url->sock_type = SOCK_OPEN;
}

/*
 * Scan the received header for interesting fields. Since C does not have
 * tools for working with potentially unterminated strings this is quite
 * long and ugly.
 *
 * Return the length of the header in case part of the data was
 * read with the header.
 * Content-Length means different thing whith GET and HEAD.
 */

static ssize_t
parse_header(struct_url *url, const char *buf, size_t bytes,
    const char *method, off_t * content_length, int expect)
{
	/* FIXME check the header parser */
	int status;
	const char *ptr = buf;
	const char *end;
	int seen_accept = 0, seen_length = 0, seen_close = 0;

	if (bytes <= 0) {
		errno = EINVAL;
		return -1;
	}

	int is_post = strcmp(method, "POST") == 0;
	int is_del = strcmp(method, "DELETE") == 0;
	int is_main_url = *url->name == 0;

	if (is_del) {
		seen_accept = 1;
		seen_length = 1;
	}

	end = memchr(ptr, '\n', bytes);
	if (!end) {
		http_report ( "reply does not contain newline!", method, buf, 0);
		errno = EIO;
		return -1;
	}
	end = ptr;
	while(1) {
		end = memchr(end + 1, '\n', bytes - (size_t)(end - ptr));
		if (!end || ((end + 1) >= (ptr + bytes))) {
			http_report ("reply does not contain end of header!",
			    method, buf, bytes);
			errno = EIO;
			return -1;
		}
		if (mempref(end, "\n\r\n", bytes - (size_t)(end - ptr), 1)) break;
	}
	ssize_t header_len = (end + 3) - ptr;

	trace("=== REPL ===\n %.*s", (int)header_len, ptr);

	end = memchr(ptr, '\n', bytes);
	char *http = "HTTP/1.1 ";
	if (!mempref(ptr, http, (size_t)(end - ptr), 1) || !isdigit( *(ptr + strlen(http)))) {
		http_report ("reply does not contain status!",
		    method, buf, (size_t)header_len);
		errno = EIO;
		return -1;
	}
	status = (int)strtol( ptr + strlen(http), (char **)&ptr, 10);
	if (status == 301 || status == 302 || status == 307 || status == 303) {
		char *location = "Location: ";
		ptrdiff_t llen = (ptrdiff_t) strlen(location);

		while(1) {
			ptr = end+1;
			if (!(ptr < buf + (header_len - 4))) {
				close_client_force(url);
				http_report("redirect did not contain a Location header!",
				    method, buf, 0);
				errno = ENOENT;
				return -1;
			}

			end = memchr(ptr, '\n', bytes - (size_t)(ptr - buf));
			if (mempref(ptr, location, (size_t)(end - ptr), 0)) {
				size_t len = (size_t) (end - ptr - llen);
				char *tmp = malloc(len + 1);
				int res;

				tmp[len] = 0;
				strncpy(tmp, ptr + llen, len);

				url->redirect_depth ++;
				if (url->redirect_depth > MAX_REDIRECTS) {
					fprintf(stderr, "%s: server redirected %i times already. Giving up.",
					    url->tname, MAX_REDIRECTS);
					errno = EIO;
					return -1;
				}

				if (status == 301) {
					trace("%s: permanent redirect to %s\n", url->tname, tmp);

					res = parse_url(tmp, url, URL_SAVE);
				} else {
					trace("%s: temporary redirect to %s\n", url->tname, tmp);

					url->redirected = 1;
					res = parse_url(tmp, url, URL_DROP);
					free(tmp);
				}

				if (res < 0) {
					errno = EIO;
					return res;
				}

				print_url(stderr, url);
				return -EAGAIN;
			}
		}
	}
	if (status != expect) {
		if (status == 401) {
			/* retry on expired session */
			if (url->sid)
				free(url->sid);
			url->sid = NULL;
			return -EAGAIN;
		}
		if (status == 404)
			errno = ENOENT;
		else {
			fprintf(stderr, "%s: failed with status: %d%.*s. Expected: %d\n",
			    method, status, (int)((end - ptr) - 1), ptr, expect);
			if (main_url.log_level)
				fprintf(stderr, buf, bytes);
			errno = EIO;
		}
		return -1;
	}

	if (is_post) {
		seen_length = 1;
		*content_length = 0;
	}

	char *content_length_str = "Content-Length: ";
	char *accept = "Accept-Ranges: bytes";
	char *date = "Last-Modified: ";
	char *close = "Connection: close";
	char *sid_str = "x-session-id: ";
	struct tm tm;
	while(1)
	{
		ptr = end+1;
		if (!(ptr < buf + (header_len - 4))) {
			if (seen_accept && seen_length) {
				if (url->sock_type == SOCK_OPEN && !seen_close)
					url->sock_type = SOCK_KEEPALIVE;
				if (url->sock_type == SOCK_KEEPALIVE && seen_close)
					url->sock_type = SOCK_OPEN;
				return header_len;
			}
			close_client_force(url);
			errno = EIO;
			if (!seen_accept) {
				http_report("server must Accept-Range: bytes",
				    method, buf, 0);
				return -1;
			}
			if (!seen_length) {
				http_report("reply didn't contain Content-Length!",
				    method, buf, 0);
				return -1;
			}
			/* fallback - should not reach */
			http_report("error parsing header.",
			    method, buf, 0);
			return -1;

		}
		end = memchr(ptr, '\n', bytes - (size_t)(ptr - buf));
		if (mempref(ptr, content_length_str, (size_t)(end - ptr), 0)
		    && isdigit( *(ptr + strlen(content_length_str)))) {
			*content_length = atoll(ptr + strlen(content_length_str));
			seen_length = 1;
			continue;
		}
		if (!is_main_url && mempref(ptr, sid_str, (size_t)(end - ptr), 0)) {
			if (url->sid)
				free(url->sid);
			url->sid = strndup(ptr + strlen(sid_str), (size_t)(end - (ptr + strlen(sid_str)) + 1));
			url->sid[end - (ptr + strlen(sid_str)) - 1] = 0;
                       continue;
		}
		if (mempref(ptr, accept, (size_t)(end - ptr), 0)) {
			seen_accept = 1;
			continue;
		}
		if (mempref(ptr, date, (size_t)(end - ptr), 0)) {
			memset(&tm, 0, sizeof(tm));
			if (!strptime(ptr + strlen(date),
				    "%n%a, %d %b %Y %T %Z", &tm)) {
				http_report("invalid time",
				    method, ptr + strlen(date),
				    (size_t)(end - ptr) - strlen(date)) ;
				continue;
			}
			url->last_modified = mktime(&tm);
			continue;
		}
		if (mempref(ptr, close, (size_t)(end - ptr), 0)) {
			seen_close = 1;
		}
	}
}

/*
 * Send the header, and get a reply.
 * This relies on 1k reads and writes being generally atomic -
 * - they fit into a single frame. The header should fit into that
 * and we do not need partial read handling so the exchange is simple.
 * However, broken sockets have to be handled here.
 */

static ssize_t
exchange(struct_url *url, char *buf, const char *method,
    off_t * content_length, off_t start, off_t end, size_t * header_length,
    const char *data, char *comp)
{
	ssize_t res;
	size_t bytes;
	int range = (end > 0);
	int is_post = strcmp(method, "POST") == 0;
	int is_del = strcmp(method, "DELETE") == 0;
	int is_head = strcmp(method, "HEAD") == 0;
	int is_finalize = !range;
	intmax_t len = range ? ((intmax_t)end - (intmax_t)start + 1) : 0;
	char fullpath[2048];

	if (*url->name)
		sprintf(fullpath, "%s/%s", url->path, url->name);
	else {
		sprintf(fullpath, "%s", url->path);
		is_finalize = 1; /* bucket op - always finalize */
	}
req:
	/* Build request buffer, starting with the request method. */

	bytes = (size_t)snprintf(buf, HEADER_SIZE, "%s %s?comp=%s%s HTTP/1.1\r\nHost: %s:%d\r\n",
	    method, fullpath, comp, (is_finalize ? "&finalize" : ""), url->host, url->port);
	bytes += (size_t)snprintf(buf + bytes, HEADER_SIZE - bytes,
	    "User-Agent: %s %s\r\n", __FILE__, VERSION);
	bytes += (size_t)snprintf(buf + bytes, HEADER_SIZE - bytes,
	    "x-ccow-offset: %" PRIdMAX "\r\nx-ccow-length: %" PRIdMAX "\r\n",
	    (intmax_t)start, len);
	if (strcmp(comp, "kv") == 0)
		bytes += (size_t)snprintf(buf + bytes, HEADER_SIZE - bytes,
		    "Content-Type: text/csv\r\n");
	else if (url->sid)
		bytes += (size_t)snprintf(buf + bytes, HEADER_SIZE - bytes,
		    "x-session-id: %s\r\n", url->sid);
	else if (url->truncate) { // CREATE or TRUNCATE (-o atomic_o_trunc)
		bytes += (size_t)snprintf(buf + bytes, HEADER_SIZE - bytes,
		    "x-ccow-object-oflags: 3\r\n");
		url->truncate = 0;
	}
	if (is_post) {
		bytes += (size_t)snprintf(buf + bytes, HEADER_SIZE - bytes,
		    "Content-Type: application/octet-stream\r\n");
		bytes += (size_t)snprintf(buf + bytes, HEADER_SIZE - bytes,
		    "Content-Length: %" PRIdMAX "\r\n", len);
	}
	bytes += (size_t)snprintf(buf + bytes, HEADER_SIZE - bytes,
	    "Connection: keep-alive\r\n");
#ifdef USE_AUTH
	if (url->auth)
		bytes += (size_t)snprintf(buf + bytes, HEADER_SIZE - bytes,
		    "Authorization: Basic %s\r\n", url->auth);
#endif
	bytes += (size_t)snprintf(buf + bytes, HEADER_SIZE - bytes, "\r\n");

	trace("=== HTTP HDR ctx=%p ===\r\n%s", url, buf);

	/* Now actually send it. */
	while (1) {
		/*
		 * It looks like the sockets abandoned by the server do not go away.
		 * Instead of returning EPIPE they allow zero writes and zero reads. So
		 * this is the place where a stale socket would be detected.
		 *
		 * Socket that return EAGAIN cause long delays. Reopen.
		 *
		 * Reset errno because reads/writes of 0 bytes are a success and are not
		 * required to touch it but are handled as error below.
		 *
		 */
#define CONNFAIL ((res <= 0) && ! errno) || (errno == EAGAIN) || (errno == EPIPE)

		errno = 0;
		res = write_client_socket(url, buf, bytes);

#ifdef RETRY_ON_RESET
		if ((errno == ECONNRESET) && (url->resets < url->retry_reset)) {
			errno_report("exchange: sleeping");
			sleep(1U << url->resets);
			url->resets ++;
			if (close_client_force(url) == -EAGAIN)
				goto req;
			continue;
		}
		url->resets = 0;
#endif
		if (CONNFAIL) {
			errno_report("exchange: failed to send request, retrying");
			if (close_client_force(url) == -EAGAIN)
				goto req;
			continue;
		}
		if (res <= 0) {
			errno_report("exchange: failed to send request");
			if (close_client_force(url) == -EAGAIN)
				goto req;
			if (!errno)
				errno = EIO;
			return res;
		}

		if (is_finalize) {
			if (url->sid)
				free(url->sid);
			url->sid = NULL;
		}

		if (is_post && range) {
			res = write_client_socket(url, data, (size_t)len);
		}

		if (res > 0) {
			res = read_client_socket(url, buf, HEADER_SIZE);
		}

#ifdef RETRY_ON_RESET
		if ((errno == ECONNRESET) && (url->resets < url->retry_reset)) {
			errno_report("exchange: sleeping");
			sleep(1U << url->resets);
			url->resets ++;
			if (close_client_force(url) == -EAGAIN)
				goto req;
			continue;
		}
		url->resets = 0;
#endif
		if (CONNFAIL) {
			errno_report("exchange: did not receive a reply, retrying");
			sleep(1);
			if (close_client_force(url) == -EAGAIN)
				goto req;
			continue;
		} else if (res <= 0) {
			errno_report("exchange: failed receving reply from server");
			if (close_client_force(url) == -EAGAIN)
				goto req;
			if (!errno)
				errno = EIO;
			return res;
		} else {
			bytes = (size_t)res;

			res = parse_header(url, buf, bytes, method, content_length,
			    (range && !is_post) ? 206 :
			    (is_del) ? 204 : 200);
			if (res == -EAGAIN) /* redirect */
				goto req;

			if (res <= 0) {
				if (!is_head || errno != ENOENT)
					http_report("exchange: server error", method, buf, bytes);
				return res;
			}

			if (header_length) *header_length = (size_t)res;

			return (ssize_t)bytes;
		}
	}
}

/*
 * Function uses HEAD-HTTP-Request
 * to determine the file size
 */

static off_t get_stat(struct_url *url, struct stat * stbuf)
{
	char buf[HEADER_SIZE];
	ssize_t bytes;

	trace("name=%s sid=%s\n", url->name, url->sid);
	pthread_mutex_lock(&tab_mutex);
	bytes = exchange(url, buf, "HEAD", &(url->file_size), 0, 0, 0, NULL, "streamsession");
	pthread_mutex_unlock(&tab_mutex);
	if (bytes < 0)
		return -1;

	close_client_socket(url);

	stbuf->st_mtime = url->last_modified;
	return stbuf->st_size = url->file_size;
}

/*
 * get_data does all the magic
 * a GET-Request with Range-Header
 * allows to read arbitrary bytes
 */

static ssize_t get_data(struct_url *url, off_t start, size_t size, char *destination)
{
	char buf[HEADER_SIZE];
	const char *b;
	ssize_t bytes;
	off_t end = start + (off_t)size - 1;
	off_t content_length;
	size_t header_length;

	pthread_mutex_lock(&url->sid_mutex);
	bytes = exchange(url, buf, "GET", &content_length,
	    start, end, &header_length, NULL, "streamsession");
	if (bytes <= 0) {
		pthread_mutex_unlock(&url->sid_mutex);
		return -1;
	}

	trace("content_length %ld size %ld sid=%s\n", content_length, size, url->sid);
	if (content_length != size) {
		http_report("didn't yield the whole piece.", "GET", 0, 0);
		size = min((size_t)content_length, size);
	}


	b = buf + header_length;

	bytes -= (b - buf);
	memcpy(destination, b, (size_t)bytes);
	size -= (size_t)bytes;
	destination +=bytes;
	for (; size > 0; size -= (size_t)bytes, destination += bytes) {

		bytes = read_client_socket(url, destination, size);
		if (bytes < 0) {
			pthread_mutex_unlock(&url->sid_mutex);
			errno_report("GET (read)");
			return -1;
		}
		if (bytes == 0) {
			break;
		}
	}
	pthread_mutex_unlock(&url->sid_mutex);

	close_client_socket(url);

	return (ssize_t)(end - start) + 1 - (ssize_t)size;
}

/*
 * post_data does all the magic
 * a POST-Request with Range-Header
 * allows to write arbitrary bytes
 */

static ssize_t post_data(struct_url *url, const char *data, off_t start,
    size_t size)
{
	char buf[HEADER_SIZE];
	off_t end = 0;
	off_t content_length;
	size_t header_length;
	ssize_t res = 0;

	trace("sid=%s\n", url->sid);
	if (size)
		end = start + (off_t)size - 1;

	pthread_mutex_lock(&url->sid_mutex);
	res = exchange(url, buf, "POST", &content_length,
	    start, end, &header_length, data, "streamsession");
	pthread_mutex_unlock(&url->sid_mutex);
	if (res <= 0)
		return -1;

	close_client_socket(url);

	return (ssize_t)size;
}

/*
 * del_data does all the magic
 * a DELETE-Request
 * allows to delete an object
 */

static int del_data(struct_url *url)
{
	char buf[HEADER_SIZE];
	off_t content_length;

	trace("sid=%s\n", url->sid);

	pthread_mutex_lock(&tab_mutex);
	if (exchange(url, buf, "DELETE", &content_length, 0, 0, 0, NULL, "streamsession") < 0)
		return -1;
	pthread_mutex_unlock(&tab_mutex);

	close_client_socket(url);

	return 0;
}

/*
 * list_data does all the magic
 * a GET-Request with offset to populte directory
 */

static ssize_t list_data(struct_url *url, off_t off, size_t size,
    fuse_req_t req, struct dirbuf *db)
{
	char buf[HEADER_SIZE];
	ssize_t bytes;
	off_t end = off + (off_t)size - 1;
	off_t content_length;
	size_t header_length;
	char *destination = url->req_buf;
	const char *b;

	pthread_mutex_lock(&tab_mutex);
	bytes = exchange(url, buf, "GET", &content_length,
	    off, end, &header_length, NULL, "kv");
	if (bytes <= 0) {
		pthread_mutex_unlock(&tab_mutex);
		return -1;
	}

	trace("hdr_len=%ld content_len=%ld off=%ld size=%ld bytes=%ld\n",
	    header_length, content_length, off, size, bytes);
	if (content_length != size) {
		size = min((size_t)content_length, size);
	}

	b = buf + header_length;

	bytes -= (b - buf);
	memcpy(destination, b, (size_t)bytes);
	size -= (size_t)bytes;
	destination +=bytes;
	for (; size > 0; size -= (size_t)bytes, destination += bytes) {

		bytes = read_client_socket(url, destination, size);
		trace("read extra %ld bytes\n", bytes);
		if (bytes < 0) {
			pthread_mutex_unlock(&tab_mutex);
			errno_report("GET (read)");
			return -1;
		}
		if (bytes == 0) {
			break;
		}
	}
	pthread_mutex_unlock(&tab_mutex);

	close_client_socket(url);

	bytes = content_length;

	size_t thisoff, nextoff=0, lenentry;
	char *saveptr;
	char *line = strtok_r(url->req_buf, "\n", &saveptr);
	while (line && (line - url->req_buf) < content_length) {

		/* From the fuse_dirent_size function in
		 * fuse-2.9.3/lib/fuse_lowlevel.c and the header file
		 * fuse-2.9.3/include/fuse_kernel.h. It is the offset of
		 * the name parameter from the start of the fuse_dirent
		 * structure, plus the length of the filename,
		 * all rounded to a multiple of sizeof(__u64). */
		lenentry = ((24+strlen(line)+7)&~7UL);

		thisoff = nextoff; /* offset of this entry */
		nextoff += lenentry;

		/* Skip this entry if we weren't asked for it */
		if (thisoff >= off) {
			/* Add this to our response until we are asked to stop */
			fuse_ino_t ino = newino(line);
			dirbuf_add(req, db, line, ino);
		}
		line  = strtok_r(NULL, "\n", &saveptr);
	}

	return (ssize_t)(end - off) + 1 - (ssize_t)size;
}
