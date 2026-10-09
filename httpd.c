/*
 * httpd -- a single-process HTTP/1.1 static file server, poll(2) only.
 *
 * shortcut: single process, single thread. A fork-per-core model would use
 * the other seven cores; the ceiling is one CPU's worth of throughput, and
 * the upgrade path is SO_REUSEPORT plus fork(), which changes no parsing.
 */
#define _GNU_SOURCE   /* memmem(3), accept4(2) */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAXCONN   256     /* poll(2) slots for clients, plus the listener */
#define INBUF     8192    /* header section limit; also the read buffer */
#define OUTBUF    65536
#define MAXTARGET 2048
#define MAXBODY   (1 << 20)   /* a GET body this server will read and discard */

enum state { S_HEAD, S_BODY, S_WRITE, S_DONE };

/* Where the chunked-body drainer is in RFC 9112 7.1's grammar. */
enum chunk_state { CH_SIZE, CH_DATA, CH_CRLF, CH_TRAILER };

struct conn {
	int   fd;
	int   state;
	char  in[INBUF];
	size_t inlen;
	char  out[OUTBUF];
	size_t outlen, outoff;
	int   closing;        /* send this response, then hang up */
	int   keep;           /* this request may be followed by another */
	int   body_mode;      /* 0 none, 1 Content-Length, 2 chunked */
	long long body_left;  /* Content-Length bytes still to discard */
	long long body_total; /* chunked: total payload seen, against MAXBODY */
	long long ch_left;    /* chunked: bytes left in the current chunk */
	int   ch_state;
	int   filefd;         /* body source, or -1 */
	off_t fileoff, fileend;
	time_t last;          /* last progress of any kind */
	time_t rstart;        /* when the current request started arriving */
};

/* One parsed request. Points into conn.in, which is NUL-punched in place. */
struct req {
	char *method;
	char *target;
	int   minor;          /* HTTP/1.minor */
	char *head;           /* first header line, or NULL */
	long long clen;       /* Content-Length, or -1 if absent */
	const char *ims;      /* If-Modified-Since, unparsed */
	const char *range;    /* Range, unparsed */
	int   te_chunked;     /* Transfer-Encoding: chunked */
	int   te_seen;
	int   nhost;
	int   want_close;     /* Connection: close */
	int   want_keep;      /* Connection: keep-alive */
};

static struct conn conns[MAXCONN];
static int nconn;
static int idle_timeout = 10;   /* seconds; -t changes it */

/* The document root, as realpath(3) sees it: absolute, no symlinks left in
 * it, no trailing slash. Every served path must be inside this string. */
static char docroot[PATH_MAX];
static size_t docroot_len;

static volatile sig_atomic_t stopping;

static void on_term(int sig) { (void)sig; stopping = 1; }

static void die(const char *m) { perror(m); exit(1); }

/* ---- connection bookkeeping ---------------------------------------------- */

static void conn_close(int i)
{
	if (conns[i].filefd >= 0) close(conns[i].filefd);
	close(conns[i].fd);
	conns[i] = conns[--nconn];
}

static void out_add(struct conn *c, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(c->out + c->outlen, OUTBUF - c->outlen, fmt, ap);
	va_end(ap);
	if (n > 0 && (size_t)n < OUTBUF - c->outlen)
		c->outlen += (size_t)n;
}

static void date_hdr(char *buf, size_t n, time_t t)
{
	struct tm tm;

	gmtime_r(&t, &tm);
	strftime(buf, n, "%a, %d %b %Y %H:%M:%S GMT", &tm);
}

/*
 * Every response that is not a file body goes through here. The body is the
 * status line in text so that a human driving curl by hand sees what
 * happened, and `extra` carries the headers a particular status requires
 * (Allow: for 405, Content-Range: for 416).
 */
static void reply(struct conn *c, int code, const char *reason,
                  const char *extra, int close_now)
{
	char body[128], date[64];
	int blen;

	/* A prepared 200 can be overwritten by a 400 from the body drainer,
	 * and its descriptor would leak once per request if this were not
	 * here. */
	if (c->filefd >= 0) {
		close(c->filefd);
		c->filefd = -1;
	}
	c->fileoff = c->fileend = 0;

	blen = snprintf(body, sizeof body, "%d %s\n", code, reason);
	date_hdr(date, sizeof date, time(NULL));

	c->outlen = c->outoff = 0;
	out_add(c, "HTTP/1.1 %d %s\r\n", code, reason);
	out_add(c, "Date: %s\r\n", date);
	out_add(c, "Content-Type: text/plain\r\n");
	out_add(c, "Content-Length: %d\r\n", blen);
	if (extra)
		out_add(c, "%s", extra);
	out_add(c, "Connection: %s\r\n\r\n",
	        close_now ? "close" : "keep-alive");
	out_add(c, "%s", body);

	c->closing = close_now;
	c->state = S_WRITE;
}

/* ---- request line -------------------------------------------------------- */

/* RFC 9110 5.6.2 tchar. Anything else in a method is a malformed request. */
static int is_tchar(unsigned char ch)
{
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
	       (ch >= '0' && ch <= '9') ||
	       !!strchr("!#$%&'*+-.^_`|~", ch);
}

static int all_tchar(const char *s)
{
	if (!*s) return 0;
	for (; *s; s++)
		if (!is_tchar((unsigned char)*s)) return 0;
	return 1;
}

/*
 * Split the request line in place. Returns 0 on success, or the status code
 * to send. RFC 9112 3: exactly one SP between the three fields -- no tabs,
 * no runs of spaces, no leading whitespace. A server that is generous here
 * disagrees with the next hop about where the target ends, which is one of
 * the two classic request smuggling primitives.
 */
static int parse_reqline(char *line, struct req *r)
{
	char *sp1, *sp2, *v;

	sp1 = strchr(line, ' ');
	if (!sp1) return 400;
	*sp1 = '\0';
	sp2 = strchr(sp1 + 1, ' ');
	if (!sp2) return 400;            /* HTTP/0.9 style, not supported */
	*sp2 = '\0';

	r->method = line;
	r->target = sp1 + 1;
	v = sp2 + 1;

	if (!all_tchar(r->method)) return 400;
	if (!*r->target || strchr(r->target, ' ')) return 400;
	if (strlen(r->target) > MAXTARGET) return 414;

	/* HTTP-version is exactly "HTTP/" DIGIT "." DIGIT. */
	if (strncmp(v, "HTTP/", 5) != 0) return 400;
	if (strlen(v) != 8 || v[6] != '.' ||
	    v[5] < '0' || v[5] > '9' || v[7] < '0' || v[7] > '9')
		return 400;
	if (v[5] != '1') return 505;     /* HTTP/2 and HTTP/0.9 over TCP */
	r->minor = v[7] - '0';
	if (r->minor > 1) return 505;
	return 0;
}

/* ---- header section (RFC 9112 section 5) --------------------------------- */

static int lc(int ch) { return ch >= 'A' && ch <= 'Z' ? ch + 32 : ch; }

/* Field names are case-insensitive; `want` must be given in lower case. */
static int name_is(const char *name, const char *want)
{
	size_t i;

	for (i = 0; name[i] && want[i]; i++)
		if (lc((unsigned char)name[i]) != want[i]) return 0;
	return !name[i] && !want[i];
}

static int all_digits(const char *s)
{
	if (!*s) return 0;
	for (; *s; s++)
		if (*s < '0' || *s > '9') return 0;
	return 1;
}

/*
 * Walk the header section in place. Returns 0, or the status code to send.
 *
 * Every refusal in here is a message-framing refusal, which is why this runs
 * before the method is even looked at: if two parties can disagree about
 * where this request ends, nothing about the next one is knowable, and
 * answering 405 to a smuggling attempt would mean having parsed it.
 */
static int parse_headers(char *p, struct req *r)
{
	r->clen = -1;

	while (*p) {
		char *line = p, *nl, *colon, *v;
		size_t vl;

		nl = strstr(p, "\r\n");
		if (nl) { *nl = '\0'; p = nl + 2; }
		else      p = line + strlen(line);

		if (!*line) continue;

		/* obs-fold. RFC 9112 5.2 lets a server reject it, and
		 * accepting it means a header value can contain a line that
		 * the next hop reads as a header of its own. */
		if (*line == ' ' || *line == '\t') return 400;

		/* A bare CR or LF inside a field. The section was split on
		 * CRLF, so anything left is an embedded line terminator --
		 * the other half of the smuggling pair. */
		if (strpbrk(line, "\r\n")) return 400;

		colon = strchr(line, ':');
		if (!colon) return 400;
		*colon = '\0';

		/* This single check is what rejects "Host : x". The space is
		 * not a tchar, so it is not part of a field name, so the line
		 * is malformed -- not a header named "Host " and not a header
		 * named "Host". RFC 9112 5.1 requires rejecting it. */
		if (!all_tchar(line)) return 400;

		v = colon + 1;
		while (*v == ' ' || *v == '\t') v++;
		vl = strlen(v);
		while (vl && (v[vl - 1] == ' ' || v[vl - 1] == '\t'))
			v[--vl] = '\0';

		if (name_is(line, "content-length")) {
			long long n;
			char *end;

			/* No sign, no whitespace, no comma list. A
			 * comma-separated list of identical values is legal
			 * per RFC 9110 8.6 and is refused anyway: it exists
			 * only because something upstream merged two fields,
			 * which is the case worth refusing. */
			if (!all_digits(v)) return 400;
			errno = 0;
			n = strtoll(v, &end, 10);
			if (errno || *end) return 400;
			if (r->clen >= 0 && r->clen != n) return 400;
			r->clen = n;
		} else if (name_is(line, "transfer-encoding")) {
			r->te_seen = 1;
			if (name_is(v, "chunked")) r->te_chunked = 1;
			else return 501;
		} else if (name_is(line, "host")) {
			r->nhost++;
		} else if (name_is(line, "range")) {
			r->range = v;
		} else if (name_is(line, "if-modified-since")) {
			r->ims = v;
		} else if (name_is(line, "connection")) {
			if (strcasestr(v, "close")) r->want_close = 1;
			if (strcasestr(v, "keep-alive")) r->want_keep = 1;
		}
	}

	/* The smuggling refusal. RFC 9112 6.1: if a message has both, the
	 * Transfer-Encoding overrides Content-Length -- and 6.3 says such a
	 * message "ought to be handled as an error", because one hop will
	 * frame it by one field and the next hop by the other. Refuse. */
	if (r->te_seen && r->clen >= 0) return 400;

	/* HTTP/1.1 requires exactly one Host. Two Host fields is a routing
	 * ambiguity in front of any virtual host, here or downstream. */
	if (r->nhost > 1) return 400;
	if (r->minor >= 1 && r->nhost != 1) return 400;

	return 0;
}

/* ---- the path resolver --------------------------------------------------- */
/*
 * This is the security property of the whole program. A static file server is
 * a path traversal sink: the request target is attacker-controlled and ends up
 * in open(2). Everything below exists to make one statement true --
 *
 *   no request can cause a byte to be read from outside the document root --
 *
 * and it is stated three times over, because each layer alone has a known
 * hole:
 *
 *   1. Percent-decoding happens exactly once. "%2e%2e%2f" becomes "../" and
 *      is then caught by layer 2; "%252e%252e%252f" becomes the literal
 *      seven-character segment "%2e%2e%2f", which is a filename, not a
 *      traversal. Decoding in a loop until nothing changes is the bug that
 *      makes double encoding work.
 *   2. A ".." segment is refused outright rather than popped. Popping is what
 *      a normaliser does, and a normaliser has to be correct about every
 *      encoding of every separator to be safe. Refusing needs to be correct
 *      about one string.
 *   3. realpath(3) resolves the result and the answer must still begin with
 *      the document root. This is the layer that catches a symlink, which the
 *      first two cannot see at all: nothing in "/link/secret" looks hostile.
 *
 * shortcut: layer 3 is a check on the path, so there is a TOCTOU window
 * between realpath(3) and open(2) in which a component could be replaced by a
 * symlink. Closing it means walking the path with openat(2) and O_NOFOLLOW
 * one segment at a time and keeping the directory fd; that is the upgrade
 * path. It needs a local attacker with write access inside the document root,
 * who can already replace the file being served.
 */

static int hexval(int ch)
{
	if (ch >= '0' && ch <= '9') return ch - '0';
	if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
	if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
	return -1;
}

/* Returns 0 and fills `out`, or the status code to refuse with. */
static int resolve(const char *target, char *out, size_t outsz)
{
	char dec[MAXTARGET + 1], joined[PATH_MAX], real[PATH_MAX];
	const char *p = target;
	char *seg, *save;
	size_t n = 0, jlen;
	int jn;

	/* absolute-form. RFC 9112 3.2.2: "a server MUST accept the
	 * absolute-form in requests". Skip scheme and authority, keep the
	 * path; a target of "http://host" with no path means "/". */
	if (strncasecmp(p, "http://", 7) == 0) {
		const char *slash = strchr(p + 7, '/');
		p = slash ? slash : "/";
	}

	/* Everything else must be origin-form. asterisk-form is only for
	 * OPTIONS, authority-form only for CONNECT, and a target that does
	 * not start with "/" is a relative path -- which is exactly how a
	 * traversal is written when the leading slash is in the way. */
	if (*p != '/') return 400;

	/* "//host/path" is a network-path reference: an authority this server
	 * would silently read as a directory called "host". */
	if (p[1] == '/') return 400;

	for (; *p && *p != '?' && *p != '#'; p++) {
		int ch = (unsigned char)*p;

		if (ch == '%') {
			int hi = hexval((unsigned char)p[1]);
			int lo = hexval((unsigned char)p[2]);

			if (hi < 0 || lo < 0) return 400;
			ch = hi * 16 + lo;
			p += 2;
		}
		/* A decoded NUL ends the string for every C interface after
		 * this point: "/public.html%00.jpg" would be checked as a
		 * .jpg and opened as "/public.html". Refuse it instead. */
		if (ch == 0) return 400;
		if (ch < 0x20 || ch == 0x7f) return 400;
		if (n + 1 >= sizeof dec) return 414;
		dec[n++] = (char)ch;
	}
	dec[n] = '\0';

	jlen = strlen(docroot);
	if (jlen >= sizeof joined) return 414;
	memcpy(joined, docroot, jlen + 1);

	for (seg = strtok_r(dec, "/", &save); seg;
	     seg = strtok_r(NULL, "/", &save)) {
		if (strcmp(seg, ".") == 0) continue;
		if (strcmp(seg, "..") == 0) return 403;
		/* No dotfiles, ever. ".git", ".env", ".htpasswd" and
		 * ".ssh" are the reason, and "..." or "..\\.." are caught
		 * here too rather than by a cleverer ".." test. */
		if (seg[0] == '.') return 403;
		jn = snprintf(joined + jlen, sizeof joined - jlen, "/%s", seg);
		if (jn < 0 || (size_t)jn >= sizeof joined - jlen) return 414;
		jlen += (size_t)jn;
	}

	if (!realpath(joined, real))
		return (errno == ENOENT || errno == ENOTDIR) ? 404 : 403;

	/* The containment check. Layers 1 and 2 are defence in depth; this is
	 * the property itself, and it is the only one that sees a symlink. */
	if (strncmp(real, docroot, docroot_len) != 0) return 403;
	if (real[docroot_len] != '\0' && real[docroot_len] != '/') return 403;

	if (strlen(real) >= outsz) return 414;
	strcpy(out, real);
	return 0;
}

/* ---- HTTP dates ---------------------------------------------------------- */
/*
 * RFC 9110 5.6.7 defines one format to send -- IMF-fixdate -- and three to
 * accept, the other two being obsolete and still in the wild. All three are
 * tried here, because the alternative is answering 200 to a conditional
 * request that an old client framed correctly for its own era.
 *
 * An unparseable date is NOT an error. RFC 9110 13.1.3: "A recipient MUST
 * ignore the If-Modified-Since header field if the received field-value is
 * not a valid HTTP-date". Refusing it with 400 would be the natural thing to
 * do in a program whose other rule is to refuse everything odd, and it would
 * be wrong.
 */
static int parse_http_date(const char *s, time_t *out)
{
	static const char *fmt[] = {
		"%a, %d %b %Y %H:%M:%S GMT",    /* IMF-fixdate */
		"%A, %d-%b-%y %H:%M:%S GMT",    /* obsolete RFC 850 */
		"%a %b %d %H:%M:%S %Y",         /* obsolete asctime() */
	};
	size_t i;

	for (i = 0; i < sizeof fmt / sizeof fmt[0]; i++) {
		struct tm tm;
		char *end;

		memset(&tm, 0, sizeof tm);
		end = strptime(s, fmt[i], &tm);
		if (end && !*end) {
			*out = timegm(&tm);
			return 0;
		}
	}
	return -1;
}

/* ---- byte ranges (RFC 9110 14) ------------------------------------------- */
/*
 * Returns 0 to ignore the header and send the whole thing, 1 having set
 * *first and *last, or 416 to refuse.
 *
 * The 0 and 416 cases are different rules and are easy to swap. RFC 9110
 * 14.2: an unsatisfiable range -- one whose first-byte-pos is at or past the
 * end -- is 416. A range that is merely malformed, or in a unit this server
 * does not know, is IGNORED and the whole representation is sent. Returning
 * 416 for a typo would break a client that sent a Range it did not need.
 *
 * shortcut: one range only. A multi-range request is refused with 416
 * rather than answered with multipart/byteranges, which needs a boundary
 * generator, a per-part header block and a second body pump. Named in the
 * README as a deviation, because RFC 9110 14.2 would allow ignoring the
 * header and sending 200 instead, and 416 is the louder answer.
 */
static int parse_range(const char *v, off_t size, off_t *first, off_t *last)
{
	const char *p = v, *dash;
	char fb[32];
	long long a, b;

	if (strncasecmp(p, "bytes", 5) != 0) return 0;   /* unknown unit */
	p += 5;
	while (*p == ' ' || *p == '\t') p++;
	if (*p != '=') return 0;
	p++;
	while (*p == ' ' || *p == '\t') p++;

	if (strchr(p, ',')) return 416;                  /* multiple ranges */

	if (*p == '-') {                                 /* suffix-length */
		p++;
		if (!all_digits(p)) return 0;
		errno = 0;
		b = strtoll(p, NULL, 10);
		if (errno) b = size;                     /* absurdly large */
		if (b == 0 || size == 0) return 416;
		if (b > size) b = size;
		*first = size - (off_t)b;
		*last = size - 1;
		return 1;
	}

	dash = strchr(p, '-');
	if (!dash || (size_t)(dash - p) >= sizeof fb) return 0;
	memcpy(fb, p, (size_t)(dash - p));
	fb[dash - p] = '\0';
	if (!all_digits(fb)) return 0;
	errno = 0;
	a = strtoll(fb, NULL, 10);
	if (errno) return 416;                           /* past any size */

	if (dash[1]) {
		if (!all_digits(dash + 1)) return 0;
		errno = 0;
		b = strtoll(dash + 1, NULL, 10);
		if (errno) b = size - 1;
	} else {
		b = size - 1;
	}

	if (size == 0 || a >= size) return 416;
	if (b < a) return 0;                             /* "bytes=5-1" */
	if (b > size - 1) b = size - 1;                  /* clamp, not 416 */
	*first = (off_t)a;
	*last = (off_t)b;
	return 1;
}

/* ---- Content-Type -------------------------------------------------------- */
/*
 * By extension, and only by extension. Sniffing the content is what makes a
 * browser render an uploaded "image" as HTML, and this server has no idea
 * what the bytes are for.
 *
 * shortcut: a hard-coded table, not /etc/mime.types. Fifteen entries covers
 * what a static site is made of; the upgrade path is reading the system file
 * at startup into the same lookup, and it is a page of parsing for a list
 * that nobody here needs.
 *
 * No charset parameter. A guessed charset is a claim about bytes this server
 * has not looked at, and getting it wrong is worse than saying nothing: a
 * client that is told the wrong charset trusts it over its own detection.
 */
static const char *ctype(const char *path)
{
	static const struct { const char *ext, *type; } tab[] = {
		{ "html", "text/html" },      { "htm",  "text/html" },
		{ "txt",  "text/plain" },     { "css",  "text/css" },
		{ "js",   "text/javascript" },{ "json", "application/json" },
		{ "xml",  "application/xml" },{ "pdf",  "application/pdf" },
		{ "png",  "image/png" },      { "gif",  "image/gif" },
		{ "jpg",  "image/jpeg" },     { "jpeg", "image/jpeg" },
		{ "svg",  "image/svg+xml" },  { "ico",  "image/vnd.microsoft.icon" },
		{ "wasm", "application/wasm" },
	};
	const char *slash = strrchr(path, '/');
	const char *dot = strrchr(slash ? slash : path, '.');
	size_t i;

	if (!dot || !dot[1]) return "application/octet-stream";
	for (i = 0; i < sizeof tab / sizeof tab[0]; i++) {
		size_t j;

		for (j = 0; tab[i].ext[j]; j++)
			if (lc((unsigned char)dot[1 + j]) != tab[i].ext[j]) break;
		if (!tab[i].ext[j] && !dot[1 + j]) return tab[i].type;
	}
	return "application/octet-stream";
}

/* ---- serving a file ------------------------------------------------------ */

static void refill(struct conn *c)
{
	size_t want;
	ssize_t n;

	if (c->filefd < 0 || c->fileoff >= c->fileend) return;
	want = (size_t)(c->fileend - c->fileoff);
	if (want > OUTBUF) want = OUTBUF;
	n = pread(c->filefd, c->out, want, c->fileoff);
	if (n <= 0) {       /* truncated under us; the length is already sent */
		c->state = S_DONE;
		return;
	}
	c->fileoff += n;
	c->outlen = (size_t)n;
	c->outoff = 0;
}

static void serve(struct conn *c, struct req *r, const char *path)
{
	char date[64], lmod[64], idx[PATH_MAX];
	const char *served = path;
	struct stat st;
	off_t first, last;
	int fd, partial = 0;

	/* O_NOFOLLOW is a second, independent refusal for the final
	 * component: even if realpath(3) were wrong, a symlink here is
	 * ELOOP rather than an open file.
	 *
	 * O_NONBLOCK is not optional either, and not for the usual reason:
	 * open(2) on a FIFO with O_RDONLY blocks until a writer appears. A
	 * single-process server that does that has been killed by one request
	 * for one fifo inside the document root -- every later connection is
	 * accepted by the kernel and never answered. Found by the assertion
	 * for /fifo, which hung the whole suite.
	 */
	fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		reply(c, errno == ENOENT || errno == ENOTDIR ? 404 : 403,
		      errno == ENOENT || errno == ENOTDIR ? "Not Found"
		                                          : "Forbidden",
		      NULL, 1);
		return;
	}

	/* fstat on the descriptor, not stat on the path: the size that goes
	 * into Content-Length has to be the size of the file being read. */
	if (fstat(fd, &st) < 0) {
		close(fd);
		reply(c, 403, "Forbidden", NULL, 1);
		return;
	}

	/* A directory serves index.html if it is there, and never a listing.
	 * open(2) with O_RDONLY succeeds on a directory on Linux, so this has
	 * to be decided from fstat and not from an EISDIR that never comes. */
	if (S_ISDIR(st.st_mode)) {
		int jn = snprintf(idx, sizeof idx, "%s/index.html", path);

		close(fd);
		fd = (jn > 0 && (size_t)jn < sizeof idx)
		     ? open(idx, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
		     : -1;
		if (fd < 0 || fstat(fd, &st) < 0) {
			if (fd >= 0) close(fd);
			reply(c, 403, "Forbidden", NULL, 1);
			return;
		}
		served = idx;   /* the type comes from index.html, not the dir */
	}

	/* A fifo, a device or a socket inside the root is not a document.
	 * Serving one would block the whole process on a read. */
	if (!S_ISREG(st.st_mode)) {
		close(fd);
		reply(c, 403, "Forbidden", NULL, 1);
		return;
	}

	date_hdr(date, sizeof date, time(NULL));
	date_hdr(lmod, sizeof lmod, st.st_mtime);

	/* Conditional GET. RFC 9110 13.1.3: 304 when the representation has
	 * not been modified since the date given. Comparison is at
	 * one-second resolution because that is all an HTTP-date carries, so
	 * `mtime <= ims` and not `<`. */
	if (r->ims) {
		time_t ims;

		if (parse_http_date(r->ims, &ims) == 0 && st.st_mtime <= ims) {
			close(fd);
			c->outlen = c->outoff = 0;
			out_add(c, "HTTP/1.1 304 Not Modified\r\n");
			out_add(c, "Date: %s\r\n", date);
			out_add(c, "Last-Modified: %s\r\n", lmod);
			/* No Content-Length and no body: a 304 that claims a
			 * length desynchronises a keep-alive connection. */
			out_add(c, "Connection: %s\r\n\r\n",
			        c->keep ? "keep-alive" : "close");
			c->filefd = -1;
			c->closing = !c->keep;
			c->state = S_WRITE;
			return;
		}
	}

	first = 0;
	last = st.st_size ? st.st_size - 1 : 0;
	if (r->range) {
		int rc = parse_range(r->range, st.st_size, &first, &last);

		if (rc == 416) {
			char extra[64];

			close(fd);
			snprintf(extra, sizeof extra,
			         "Content-Range: bytes */%lld\r\n",
			         (long long)st.st_size);
			reply(c, 416, "Range Not Satisfiable", extra, 1);
			return;
		}
		partial = rc;
	}

	c->outlen = c->outoff = 0;
	out_add(c, "HTTP/1.1 %s\r\n",
	        partial ? "206 Partial Content" : "200 OK");
	out_add(c, "Date: %s\r\n", date);
	out_add(c, "Last-Modified: %s\r\n", lmod);
	out_add(c, "Content-Type: %s\r\n", ctype(served));
	out_add(c, "Accept-Ranges: bytes\r\n");
	if (partial)
		out_add(c, "Content-Range: bytes %lld-%lld/%lld\r\n",
		        (long long)first, (long long)last,
		        (long long)st.st_size);
	out_add(c, "Content-Length: %lld\r\n",
	        partial ? (long long)(last - first + 1)
	                : (long long)st.st_size);
	out_add(c, "Connection: %s\r\n\r\n",
	        c->keep ? "keep-alive" : "close");

	c->filefd = fd;
	c->fileoff = partial ? first : 0;
	c->fileend = partial ? last + 1 : st.st_size;

	/* HEAD. RFC 9110 9.3.2: the response is identical to the GET
	 * response except that there is no body. Identical means the
	 * Content-Length is still the length the GET would have sent -- it
	 * is NOT zero, and it is not omitted. Everything above this line is
	 * the same code for both methods precisely so the two cannot drift. */
	if (strcmp(r->method, "HEAD") == 0) {
		close(fd);
		c->filefd = -1;
		c->fileend = 0;
	}
	c->closing = !c->keep;
	c->state = S_WRITE;
}

/* ---- request bodies (RFC 9112 6 and 7) ----------------------------------- */
/*
 * GET and HEAD are the only methods here, and neither has any use for a
 * body -- but a body that is not read is not gone. It sits in the socket and
 * becomes the next request on a keep-alive connection, which is the second
 * half of request smuggling. So it is read and discarded, and anything
 * malformed in its framing is a 400 that closes the connection.
 *
 * The response is built BEFORE the body is drained, because it does not
 * depend on it, and sent AFTER -- a server that answers before reading the
 * request tends to find the client has stopped reading. A drain error
 * overwrites the prepared response.
 */
static void consume(struct conn *c, size_t n)
{
	memmove(c->in, c->in + n, c->inlen - n);
	c->inlen -= n;
}

/* 0 need more bytes, 1 done, otherwise the status code to refuse with. */
static int drain_body(struct conn *c)
{
	if (c->body_mode == 1) {
		size_t take = c->inlen < (size_t)c->body_left
		            ? c->inlen : (size_t)c->body_left;

		consume(c, take);
		c->body_left -= (long long)take;
		return c->body_left == 0;
	}

	for (;;) {
		char *nl;
		size_t n, take;

		switch (c->ch_state) {
		case CH_SIZE:
			nl = memmem(c->in, c->inlen, "\r\n", 2);
			if (!nl)      /* a chunk-size line cannot be this long */
				return c->inlen > 80 ? 400 : 0;
			n = (size_t)(nl - c->in);
			/* The same 80-byte ceiling has to apply when the CRLF
			 * HAS arrived, or an 83-digit chunk size padded with
			 * leading zeros parses fine and the cap above only
			 * catches a client that never sends the CRLF at all.
			 * Found by the assertion for exactly that. */
			if (n > 80) return 400;
			{
				long long sz = 0;
				size_t i;

				for (i = 0; i < n; i++) {
					int h;

					/* chunk-ext, which is legal and
					 * ignored. */
					if (c->in[i] == ';') break;
					h = hexval((unsigned char)c->in[i]);
					if (h < 0) return 400;
					/* A chunk size that overflows is the
					 * oldest chunked-encoding bug there
					 * is. */
					if (sz > (LLONG_MAX - h) / 16)
						return 400;
					sz = sz * 16 + h;
				}
				if (i == 0) return 400;   /* no hex digits */
				if (i > 16) return 400;   /* cannot be 64-bit */
				consume(c, n + 2);
				c->body_total += sz;
				if (c->body_total > MAXBODY) return 413;
				c->ch_left = sz;
				c->ch_state = sz ? CH_DATA : CH_TRAILER;
			}
			break;

		case CH_DATA:
			take = c->inlen < (size_t)c->ch_left
			     ? c->inlen : (size_t)c->ch_left;
			consume(c, take);
			c->ch_left -= (long long)take;
			if (c->ch_left) return 0;
			c->ch_state = CH_CRLF;
			break;

		case CH_CRLF:
			if (c->inlen < 2) return 0;
			if (c->in[0] != '\r' || c->in[1] != '\n') return 400;
			consume(c, 2);
			c->ch_state = CH_SIZE;
			break;

		default:  /* CH_TRAILER: fields, then an empty line */
			nl = memmem(c->in, c->inlen, "\r\n", 2);
			if (!nl)
				return c->inlen > INBUF / 2 ? 400 : 0;
			n = (size_t)(nl - c->in);
			consume(c, n + 2);
			if (n == 0) return 1;
			break;
		}
	}
}

/* ---- request handling ---------------------------------------------------- */

static void handle(struct conn *c)
{
	char *eoh, *line, *nl;
	char empty[1] = "", path[PATH_MAX];
	size_t headlen;
	struct req r;
	int code;

	memset(&r, 0, sizeof r);

	eoh = memmem(c->in, c->inlen, "\r\n\r\n", 4);
	headlen = (size_t)(eoh - c->in) + 4;

	/* A NUL anywhere in the header section. Everything after this point
	 * treats the section as C strings, so a NUL would silently truncate a
	 * target or a field value -- and the bytes behind it would be read by
	 * the next hop as something else entirely. */
	if (memchr(c->in, '\0', (size_t)(eoh - c->in))) {
		reply(c, 400, "Bad Request", NULL, 1);
		return;
	}
	*eoh = '\0';                     /* the header section is now a string */
	line = c->in;
	nl = strstr(line, "\r\n");
	if (nl) {
		*nl = '\0';
		r.head = nl + 2;
	}

	code = parse_reqline(line, &r);
	/* parse_headers() runs even when there is no header line at all: the
	 * "exactly one Host" rule is enforced at its end, and skipping the
	 * call for "GET / HTTP/1.1" with an empty section let that request
	 * through with no Host. Found by the assertion for it. */
	if (!code)
		code = parse_headers(r.head ? r.head : empty, &r);
	if (code) {
		reply(c, code, code == 400 ? "Bad Request"
		            : code == 414 ? "URI Too Long"
		            : code == 501 ? "Not Implemented"
		                          : "HTTP Version Not Supported",
		      NULL, 1);
		return;
	}

	/*
	 * Persistence. RFC 9112 9.3: HTTP/1.1 is persistent unless the
	 * request says "Connection: close"; HTTP/1.0 is the other way round
	 * and needs an explicit "keep-alive". Everything that refuses the
	 * request closes regardless -- once the framing is in doubt, the
	 * bytes after this request cannot be assumed to be another one.
	 */
	c->keep = r.minor >= 1 ? !r.want_close : r.want_keep;

	/* Note that every refusal from here down closes the connection, even
	 * the harmless-looking ones. They return before the body drainer has
	 * run, so the request's body -- if it had one -- is still in the
	 * socket, and keeping the connection open would mean reading it as
	 * the next request. 404 and 405 are not framing errors, but they are
	 * answered before the framing has been dealt with. */
	if (strcmp(r.method, "GET") != 0 && strcmp(r.method, "HEAD") != 0) {
		reply(c, 405, "Method Not Allowed", "Allow: GET, HEAD\r\n", 1);
		return;
	}

	code = resolve(r.target, path, sizeof path);
	if (code) {
		reply(c, code, code == 400 ? "Bad Request"
		            : code == 403 ? "Forbidden"
		            : code == 414 ? "URI Too Long"
		                          : "Not Found", NULL, 1);
		return;
	}
	serve(c, &r, path);

	/* The response is in c->out. Now the body, if the request declared
	 * one: drop the header section and let the drainer run. */
	consume(c, headlen);
	headlen = 0;
	if (r.clen > MAXBODY) {
		reply(c, 413, "Content Too Large", NULL, 1);
		return;
	}
	if (r.te_chunked) {
		c->body_mode = 2;
		c->ch_state = CH_SIZE;
	} else if (r.clen > 0) {
		c->body_mode = 1;
		c->body_left = r.clen;
	} else {
		return;                  /* no body: c->state is S_WRITE */
	}

	code = drain_body(c);
	if (code > 1) {
		reply(c, code, code == 413 ? "Content Too Large"
		                           : "Bad Request", NULL, 1);
		c->body_mode = 0;
	} else if (code == 0) {
		c->state = S_BODY;       /* wait for the rest of it */
	}
}

/* ---- the state machine --------------------------------------------------- */

static void on_readable(int i)
{
	struct conn *c = &conns[i];
	ssize_t n;

	n = read(c->fd, c->in + c->inlen, INBUF - 1 - c->inlen);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return;
		c->state = S_DONE;
		return;
	}
	if (n == 0) {                      /* peer finished sending */
		c->state = S_DONE;
		return;
	}
	c->inlen += (size_t)n;
	c->last = time(NULL);

	if (c->state == S_BODY) {
		int code = drain_body(c);

		if (code > 1) {
			reply(c, code, code == 413 ? "Content Too Large"
			                           : "Bad Request", NULL, 1);
			c->body_mode = 0;
		} else if (code == 1) {
			c->state = S_WRITE;
		} else if (c->inlen == INBUF - 1) {
			/* The drainer could not make progress on a full
			 * buffer: a chunk-size line or a trailer field longer
			 * than the whole buffer. */
			reply(c, 400, "Bad Request", NULL, 1);
		}
		return;
	}

	if (memmem(c->in, c->inlen, "\r\n\r\n", 4))
		handle(c);
	else if (c->inlen == INBUF - 1)
		/* The whole header section, request line included, has to fit
		 * in one buffer. 431 rather than silently truncating: a
		 * truncated header section is a different request. */
		reply(c, 431, "Request Header Fields Too Large", NULL, 1);
}

static void on_writable(int i)
{
	struct conn *c = &conns[i];
	ssize_t n;

	n = write(c->fd, c->out + c->outoff, c->outlen - c->outoff);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return;
		c->state = S_DONE;          /* EPIPE/ECONNRESET: peer went away */
		return;
	}
	c->outoff += (size_t)n;
	c->last = time(NULL);
	if (c->outoff < c->outlen)
		return;
	if (c->filefd >= 0 && c->fileoff < c->fileend) {
		refill(c);                  /* more of the body */
		return;
	}
	if (c->filefd >= 0) {
		close(c->filefd);
		c->filefd = -1;
	}
	if (c->closing) {
		c->state = S_DONE;
		return;
	}

	/* Keep-alive: the same connection, a fresh request. Everything that
	 * described the last one is cleared here; c->in is NOT, because
	 * anything still in it is the next request. A client is allowed to
	 * send several without waiting, so if a whole one is already
	 * buffered it is answered now rather than after another poll(2). */
	c->outlen = c->outoff = 0;
	c->fileoff = c->fileend = 0;
	c->body_mode = 0;
	c->body_left = c->body_total = c->ch_left = 0;
	c->ch_state = CH_SIZE;
	c->keep = 0;
	c->rstart = time(NULL);
	c->state = S_HEAD;
	if (memmem(c->in, c->inlen, "\r\n\r\n", 4))
		handle(c);
}

static int listen_on(const char *addr, int port)
{
	struct sockaddr_in sa;
	socklen_t sl = sizeof sa;
	int fd, one = 1;

	fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0) die("socket");
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons((uint16_t)port);
	if (inet_pton(AF_INET, addr, &sa.sin_addr) != 1) {
		fprintf(stderr, "httpd: bad address %s\n", addr);
		exit(2);
	}
	if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0) die("bind");
	if (listen(fd, 128) < 0) die("listen");

	/* Port 0 means "kernel, you pick"; read it back and announce it. A
	 * fixed port would collide with anything else on the machine. */
	if (getsockname(fd, (struct sockaddr *)&sa, &sl) < 0) die("getsockname");
	printf("listening %s:%d\n", addr, ntohs(sa.sin_port));
	fflush(stdout);
	return fd;
}

int main(int argc, char **argv)
{
	struct pollfd pfd[MAXCONN + 1];
	const char *addr = "127.0.0.1";
	const char *root = ".";
	int port = 0, lfd, opt;

	/* Writing to a peer that has closed must be an errno, not a death. */
	signal(SIGPIPE, SIG_IGN);

	/* An orderly exit on SIGTERM is not politeness. LeakSanitizer only
	 * runs at normal process exit, so a server that is always killed
	 * outright is a server whose `make test-asan` can never report a
	 * leak -- the target would be unable to detect one of the two defect
	 * classes it exists for. */
	signal(SIGTERM, on_term);
	signal(SIGINT, on_term);

	while ((opt = getopt(argc, argv, "a:p:r:t:")) != -1) {
		switch (opt) {
		case 'a': addr = optarg; break;
		case 'r': root = optarg; break;
		case 'p': port = atoi(optarg); break;
		case 't': idle_timeout = atoi(optarg); break;
		default:
			fprintf(stderr, "usage: httpd [-a addr] [-p port] "
			                "[-r docroot] [-t idle_seconds]\n");
			return 2;
		}
	}

	/* Resolve the root once, at startup, with no symlinks left in it.
	 * Comparing a request's realpath against an unresolved root would
	 * fail for every root reached through a symlink -- and /tmp is one
	 * on plenty of systems. */
	if (!realpath(root, docroot)) {
		fprintf(stderr, "httpd: %s: %s\n", root, strerror(errno));
		return 1;
	}
	docroot_len = strlen(docroot);
	if (docroot_len == 1)       /* root is "/": every path is inside it */
		docroot_len = 0;

	lfd = listen_on(addr, port);

	while (!stopping) {
		int n, i;
		time_t now;

		pfd[0].fd = lfd;
		pfd[0].events = nconn < MAXCONN ? POLLIN : 0;
		pfd[0].revents = 0;
		for (i = 0; i < nconn; i++) {
			pfd[i + 1].fd = conns[i].fd;
			pfd[i + 1].events = conns[i].state == S_WRITE
			                  ? POLLOUT : POLLIN;
			pfd[i + 1].revents = 0;
		}

		n = poll(pfd, (nfds_t)nconn + 1, 1000);
		if (n < 0) {
			if (errno == EINTR) continue;
			die("poll");
		}

		/* Connections first, so that pfd[i + 1] still describes conns[i].
		 * Walking backwards keeps that true across conn_close(), which
		 * moves the last slot down into the one it just freed. */
		for (i = nconn - 1; i >= 0; i--) {
			short r = pfd[i + 1].revents;

			if (r & POLLOUT)
				on_writable(i);
			else if (r & (POLLERR | POLLNVAL))
				conns[i].state = S_DONE;
			else if (r & (POLLIN | POLLHUP))
				on_readable(i);

			if (conns[i].state == S_DONE)
				conn_close(i);
		}

		if (pfd[0].revents & POLLIN) {
			int cfd = accept4(lfd, NULL, NULL, SOCK_NONBLOCK);
			if (cfd >= 0) {
				memset(&conns[nconn], 0, sizeof conns[0]);
				conns[nconn].fd = cfd;
				conns[nconn].filefd = -1;
				conns[nconn].state = S_HEAD;
				conns[nconn].last = conns[nconn].rstart = time(NULL);
				nconn++;
			}
		}

		/*
		 * Reaping, and the distinction here is the whole slow-loris
		 * answer. A plain idle timeout -- "close if nothing has
		 * arrived for N seconds" -- does not stop a loris at all,
		 * because one byte every N-1 seconds resets it forever. So
		 * while a request is still arriving, the deadline is on the
		 * REQUEST: it must be complete within idle_timeout seconds of
		 * its first byte, however busily the client dribbles.
		 *
		 * While a response is being written the deadline is the
		 * ordinary idle one, measured from the last byte that moved,
		 * because a large body legitimately takes a long time and a
		 * slow reader is a customer rather than an attack.
		 */
		now = time(NULL);
		for (i = nconn - 1; i >= 0; i--) {
			struct conn *c = &conns[i];

			if (c->state == S_WRITE) {
				if (now - c->last > idle_timeout)
					conn_close(i);
			} else if (now - c->rstart > idle_timeout) {
				if (c->inlen == 0) {
					/* An idle keep-alive connection that
					 * never started another request.
					 * Nothing to answer; just close. */
					conn_close(i);
				} else {
					reply(c, 408, "Request Timeout",
					      NULL, 1);
				}
			}
		}
	}

	while (nconn) conn_close(nconn - 1);
	close(lfd);
	return 0;
}
