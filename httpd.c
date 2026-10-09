/*
 * httpd -- a single-process HTTP/1.1 static file server, poll(2) only.
 *
 * Stage 1: the listening socket and the poll loop. Every connection is read
 * until the end of the header section and answered with a fixed response.
 * Parsing, path resolution and file serving arrive in later commits; what is
 * being established here is the thing all of them sit on -- a non-blocking
 * accept/read/write state machine that one slow or rude client cannot stall.
 *
 * shortcut: single process, single thread. A fork-per-core model would use
 * the other seven cores; the ceiling is one CPU's worth of throughput, and
 * the upgrade path is SO_REUSEPORT plus fork(), which changes no parsing.
 */
#define _GNU_SOURCE   /* memmem(3), accept4(2) */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAXCONN   256     /* poll(2) slots for clients, plus the listener */
#define INBUF     8192    /* header section limit; also the read buffer */
#define OUTBUF    65536

enum state { S_HEAD, S_WRITE, S_DONE };

struct conn {
	int   fd;
	int   state;
	char  in[INBUF];
	size_t inlen;
	char  out[OUTBUF];
	size_t outlen, outoff;
	int   closing;        /* send this response, then hang up */
	time_t last;          /* for the idle timeout */
};

static struct conn conns[MAXCONN];
static int nconn;
static int idle_timeout = 10;   /* seconds; -t changes it */

static void die(const char *m) { perror(m); exit(1); }

/* ---- connection bookkeeping ---------------------------------------------- */

static void conn_close(int i)
{
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

/* ---- the fixed stage-1 response ------------------------------------------ */

static void respond(struct conn *c)
{
	static const char body[] = "httpd\n";

	out_add(c, "HTTP/1.1 200 OK\r\n");
	out_add(c, "Content-Type: text/plain\r\n");
	out_add(c, "Content-Length: %zu\r\n", sizeof body - 1);
	out_add(c, "Connection: close\r\n\r\n");
	out_add(c, "%s", body);
	c->closing = 1;
	c->state = S_WRITE;
}

/* ---- the state machine --------------------------------------------------- */

static void on_readable(int i)
{
	struct conn *c = &conns[i];
	ssize_t n;

	n = read(c->fd, c->in + c->inlen, INBUF - c->inlen);
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

	if (memmem(c->in, c->inlen, "\r\n\r\n", 4))
		respond(c);
	else if (c->inlen == INBUF)        /* header section too large */
		c->state = S_DONE;
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
	if (c->outoff == c->outlen)
		c->state = S_DONE;
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
	int port = 0, lfd, opt;

	/* Writing to a peer that has closed must be an errno, not a death. */
	signal(SIGPIPE, SIG_IGN);

	while ((opt = getopt(argc, argv, "a:p:t:")) != -1) {
		switch (opt) {
		case 'a': addr = optarg; break;
		case 'p': port = atoi(optarg); break;
		case 't': idle_timeout = atoi(optarg); break;
		default:
			fprintf(stderr, "usage: httpd [-a addr] [-p port] "
			                "[-t idle_seconds]\n");
			return 2;
		}
	}

	lfd = listen_on(addr, port);

	for (;;) {
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
				conns[nconn].state = S_HEAD;
				conns[nconn].last = time(NULL);
				nconn++;
			}
		}

		/* Idle reaping. A client that opens a connection and says
		 * nothing, or dribbles one byte a minute, holds a slot
		 * otherwise. */
		now = time(NULL);
		for (i = nconn - 1; i >= 0; i--)
			if (now - conns[i].last > idle_timeout)
				conn_close(i);
	}
}
