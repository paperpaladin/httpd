# httpd

A single-process HTTP/1.1 static file server in one C11 file, using `poll(2)`
for concurrency.

```sh
make
./httpd -r /srv/www          # prints: listening 127.0.0.1:41287
make test
make test-asan
```

```
httpd [-a addr] [-p port] [-r docroot] [-t idle_seconds]
```

The port defaults to 0, which means the kernel picks one, and the chosen port
is printed on stdout and flushed before the first `accept(2)`. There is no
configuration file, no virtual hosting, no TLS, no CGI, and no directory
listing.

Pure C11, gcc, no libraries. `poll(2)` and plain sockets.

## Security

A static file server is a path traversal sink: the request target is chosen
by whoever is talking to it and ends up in `open(2)`. One statement has to be
true, and the rest of this section is about how it is made true and how it is
proved:

> **No request can cause a byte to be read from outside the document root.**

### Three layers, because each one alone has a hole

1. **Percent-decoding happens exactly once.** `%2e%2e%2f` becomes `../` and is
   then caught by layer 2. `%252e%252e%252f` becomes the literal nine-byte
   segment `%2e%2e%2f`, which is a filename and not a traversal -- so the
   correct answer for the double-encoded form is **404**, because no such file
   exists. Decoding in a loop until the string stops changing is the bug that
   makes double encoding work, so there is no loop.
2. **A `..` segment is refused, not popped.** Popping is what a normaliser
   does, and a normaliser has to be correct about every encoding of every
   separator in order to be safe. Refusing has to be correct about one string.
   Any segment beginning with `.` is refused as well, which is also the
   no-dotfiles rule.
3. **`realpath(3)` containment.** The resolved path must still begin with the
   document root, which is itself `realpath`'d once at startup. This is the
   only layer that can see a symlink: there is nothing hostile in the string
   `/escape`.

### The oracle: a secret file outside the root

`t/run.sh` writes `SUPERSECRET-5f3a9c-DO-NOT-SERVE` into a file **outside** the
document root, puts a symlink to it **inside** the root, and puts a second
symlink to the whole parent directory inside the root as well. Every refusal
assertion checks two things: a refusing status code, and that the secret string
is not in the response body. A 200 with the wrong body and a 403 with the right
one are both failures, and only one of them is visible in a status code.

Every response body the suite ever receives is also appended to one file, which
is grepped once at the end (`deny: secret never served`). A check against only
the last response is an assertion about one request that happened to be
refused.

### What is refused, and the assertion that proves it

| Attack | Answer | Assertion in `t/run.sh` |
| --- | --- | --- |
| `/../secret.txt` | 403 | `deny: dot-dot` |
| `/../../etc/passwd` | 403 | `deny: dot-dot twice` |
| `/sub/../../secret.txt` | 403 | `deny: dot-dot after a dir` |
| `/./../secret.txt` | 403 | `deny: dot then dot-dot` |
| `/sub/..` | 403 | `deny: dot-dot trailing` |
| `/%2e%2e/secret.txt` | 403 | `deny: encoded dot-dot` |
| `/%2e%2e%2fsecret.txt` | 403 | `deny: encoded dot-dot-slash` |
| `/..%2fsecret.txt` | 403 | `deny: half-encoded` |
| `/%2E%2E%2Fsecret.txt` | 403 | `deny: upper-case hex` |
| `/sub/%2e%2e/%2e%2e/secret.txt` | 403 | `deny: encoded dot-dot deep` |
| `/%252e%252e%252fsecret.txt` | **404** | `deny: double-encoded` |
| `/%25252e%25252e%25252fsecret.txt` | **404** | `deny: triple-encoded` |
| `/....//secret.txt` | 403 | `deny: four dots` |
| `/..;/secret.txt` | 403 | `deny: dot-dot semicolon` |
| `/..\..\secret.txt` | 403 | `deny: backslash separators` |
| `/etc/passwd` (absolute-looking) | 404 | `deny: absolute /etc/passwd` |
| `//ok.txt` (network-path reference) | 400 | `deny: network-path reference` |
| `GET ../secret.txt HTTP/1.1` (relative target) | 400 | `raw: relative target` |
| `GET * HTTP/1.1` (asterisk-form) | 400 | `raw: asterisk-form target` |
| `GET http://x/../secret.txt HTTP/1.1` | 403 | `raw: absolute-form traversal` |
| `/ok.txt%00.jpg` (NUL truncation) | 400 | `deny: NUL via %00` |
| `/%00` | 400 | `deny: bare %00` |
| literal NUL byte in the request target | 400 | `raw: literal NUL in target` |
| literal NUL byte in a field value | 400 | `raw: literal NUL in a field` |
| `/%zz`, `/%2` (bad escapes) | 400 | `deny: bad percent escape`, `deny: truncated escape` |
| `/ok%0d%0atxt` (encoded CRLF) | 400 | `deny: encoded CR` |
| `/ok%7f.txt` (encoded DEL) | 400 | `deny: encoded DEL` |
| `/escape` -> symlink to a file outside the root | 403 | `deny: symlink to a file outside` |
| `/escapedir/secret.txt` -> symlink to the parent dir | 403 | `deny: symlink to a dir outside` |
| `/escapedir/` -> listing through that symlink | 403 | `deny: symlink dir, dir listing` |
| `/.hidden` (dotfile) | 403 | `deny: dotfile` |
| `/.git/config` (dot directory) | 403 | `deny: dot directory` |
| `/%2ehidden` (encoded dotfile) | 403 | `deny: encoded dotfile` |
| `/nodir/` (directory, no index.html) | 403 | `serve: dir with no index` |
| `/fifo` (a FIFO inside the root) | 403 | `serve: a fifo is not a doc` |

A symlink that stays **inside** the root is served (`serve: symlink inside
root`), because it is a document and not an escape. Sixteen assertions for what
the resolver must still serve come before the refusals in the file, for the
reason that a resolver which refuses everything satisfies every refusal test
ever written.

### Request smuggling

Two refusals, both from RFC 9112:

- **Content-Length together with Transfer-Encoding** is 400, in both field
  orders. Section 6.1 permits resolving it in favour of Transfer-Encoding and
  6.3 says such a message "ought to be handled as an error"; it is an error
  here, because one hop frames the message by one field and the next hop by
  the other.
- **Whitespace before the colon** in a header line is 400, as section 5.1
  requires. `Host : evil` is not a field named `Host ` and is not normalised
  into `Host`: it is a malformed line. An intermediary that trims the space
  and a server that does not now disagree about the Host of the request.

Also refused as framing errors: two conflicting `Content-Length` fields,
`Content-Length` as a comma list, signed, hex, empty or large enough to
overflow `strtoll`, obs-fold continuation lines, a bare CR or LF surviving
inside a field value, a NUL anywhere in the header section, and a missing or
duplicated `Host` on HTTP/1.1.

And the other half of smuggling: the request **body** is read and discarded
even for GET, because a body that is not read is not gone -- it stays in the
socket and becomes the next request on a keep-alive connection. The assertion
`pipeline: body is not a request` sends a request whose 39-byte body reads
`GET /sub/deep.txt HTTP/1.1...` and requires exactly one response.

### Mutation testing of the security property

Three mutants were built and run through the whole suite:

| Mutation | Verdict |
| --- | --- |
| delete the `realpath(3)` containment check | **caught**: 3 failures, including `deny: secret never served` with the secret in a body |
| delete both the containment check and the `..` refusal | **caught**: the secret is served with 200 |
| delete the `..` refusal alone | **SURVIVES** -- all assertions pass |

The surviving mutant is honest and expected: layer 3 catches every `..` case
the suite can construct, because `realpath` either resolves outside the root
(403) or fails (404). Layer 2 is kept anyway, because it refuses before
touching the filesystem at all and because it makes the refusal independent of
`realpath(3)` being right. If you want a test that fails when layer 2 is
removed, it has to be one where `realpath` succeeds inside the root -- the
stricter-than-necessary refusal of `/sub/../ok.txt`.

## The oracle

`curl` is the authority. Every assertion drives a real `curl` against a real
server on a real socket, and the thing asserted is the status code curl
reports, the header block curl saved, or the bytes curl wrote to a file.
Nothing in the suite inspects httpd's memory or trusts it about anything.

Five other outside authorities are used where curl cannot answer:

| Oracle | What it decides | Why it is independent |
| --- | --- | --- |
| `curl` | status codes, headers, bodies, `%{content_type}`, `%{num_connects}` | a different program by other people implementing the same RFC |
| `cmp(1)` with `tail`/`head` | byte-for-byte file and range integrity | coreutils does the offset arithmetic, not us |
| `file(1)` | Content-Type for 4 fixtures | reads the file's **content**; httpd reads its **name** |
| `date(1)` | the `Last-Modified` value | formats the same mtime through different code |
| `/proc/PID/status` | SIGPIPE is ignored | the kernel's own view of the live process |
| `t/raw.py` | malformed requests | **ours**, and therefore the weakest -- see below |

`t/raw.py` exists because curl is a correct client: it will not put a space
before a colon, send two conflicting `Content-Length` headers, or dribble a
request line one byte per second. Assertions driven by it are printed with a
`raw:` prefix and are a weaker kind of evidence, because the request is ours
even though the verdict is httpd's.

`%{num_connects}` deserves a note: it is curl's own count of TCP connections
it had to open, so "two URLs, one connection" is a statement about the socket
that no status code can make.

## What does not work

This list is longer than the feature list, on purpose.

**Not implemented at all**

- **TLS.** No `https`. Put it behind something that does TLS, or do not.
- **CGI, PHP, FastCGI, proxying, rewriting, redirects.** Files only. There is
  not even a 301 from `/sub` to `/sub/`: both serve the same `index.html`,
  which is wrong in the strict sense that relative links in that document
  resolve differently, and is not fixed.
- **Virtual hosting.** `Host` is required on HTTP/1.1 and then ignored
  completely. Two names pointing here serve the same tree.
- **Directory listings.** A directory with no `index.html` is 403. A generated
  listing is a disclosure feature.
- **ETags and `If-None-Match`, `If-Range`, `If-Unmodified-Since`,
  `If-Match`.** `If-Modified-Since` is the only conditional.
- **Compression.** No `Content-Encoding`, no precompressed `.gz` lookup.
  `Accept-Encoding` is ignored.
- **`Content-Type` charset.** Never sent. A guessed charset is a claim about
  bytes nothing here has looked at, and a client told the wrong charset trusts
  it over its own detection.
- **Caching headers.** No `Cache-Control`, no `Expires`.
- **Access logging.** Nothing is written to stdout after the port line, and
  the suite asserts stderr stays empty.
- **IPv6.** `-a` takes an IPv4 literal; the socket is `AF_INET`.
- **Methods other than GET and HEAD.** Everything else is 405 with
  `Allow: GET, HEAD`, including methods the server has never heard of, where
  RFC 9110 would prefer 501. The distinction is not observable here, since
  nothing is implemented for any of them.

**Implemented, with a ceiling** (each one is a `shortcut:` comment in the
source naming its upgrade path)

- **One process, one thread.** One CPU's worth of throughput. The upgrade is
  `SO_REUSEPORT` plus `fork()`, which changes no parsing.
- **Multi-range requests are refused with 416.** A single range is fully
  supported in all three forms. `multipart/byteranges` needs a boundary
  generator, per-part headers and a second body pump. RFC 9110 14.2 would also
  permit ignoring the `Range` header and answering 200; 416 is the louder
  answer and it is a deliberate deviation.
- **The MIME table is hard-coded**, fifteen extensions. Not `/etc/mime.types`.
- **`realpath(3)` is a check on a path, so there is a TOCTOU window** between
  it and `open(2)` in which a path component could be replaced by a symlink.
  Closing it means walking the path with `openat(2)` and `O_NOFOLLOW` one
  segment at a time. It needs a local attacker with write access *inside* the
  document root, who can already replace the file being served.
- **The header section must fit in 8191 bytes** (431 otherwise) and the
  request target in 2048 (414). A request body is read and discarded up to
  1MiB, over which it is 413.
- **256 connections**, a compile-time constant. Past that, new connections sit
  in the listen backlog until a slot frees.
- **A refusal always closes the connection**, including 404 and 405. Those are
  answered before the body drainer has run, so the request's body may still be
  in the socket and keeping the connection open would mean reading it as the
  next request. Observable: curl opens a second connection after a 404
  (`keep: 404 closes`).
- **A bare-LF line ending is not accepted** anywhere. RFC 9112 2.2 permits a
  recipient to recognise a lone LF as a line terminator; this one requires
  CRLF, so an LF-only request is not malformed here, it simply never completes
  and is reaped by the request deadline.
- **No `Server` header.** Not a feature, just nothing to say.

**Slow loris: yes, it times out.** The answer is a deadline on the *request*,
not a timeout on inactivity. A plain idle timeout does not stop a loris at
all, because one byte every N-1 seconds resets it forever. So while a request
is still arriving it must be complete within `-t` seconds of its first byte,
however busily the client dribbles, and past that it gets 408. While a
*response* is being written the deadline is the ordinary idle one measured
from the last byte that moved, because a 10MB body legitimately takes a while
and a slow reader is a customer rather than an attack. `-t` defaults to 10
seconds. Six assertions, including the two controls that a one-second server
still answers a normal request and one dripped at 5ms per byte.

## Where curl or the RFC contradicted an assumption

- **curl normalises `%2e` away.** `curl 'http://h/%2e%2e/secret.txt'`
  percent-decodes the `%2e`, removes the resulting dot segment, and sends
  `GET /secret.txt` -- confirmed with `curl -v`. The traversal assertion was
  passing on a 404 for a file that does not exist, which is a green test for a
  request that was never made. `--path-as-is` is required. curl does *not* do
  this when the separator is also encoded (`%2e%2e%2f`), which is why only two
  of the ten encoded cases were affected.
- **An invalid `If-Modified-Since` must be ignored, not refused.** RFC 9110
  13.1.3 is explicit. Everywhere else in this program, something odd on the
  wire is a 400; here it has to be a 200 with the full body.
- **A malformed `Range` must be ignored; only an unsatisfiable one is 416.**
  RFC 9110 14.2. An unknown unit, a missing `=`, non-numeric or reversed
  positions all mean "send the whole thing". A `last-byte-pos` past the end of
  the file is neither: it is clamped.
- **`open(2)` on a FIFO with `O_RDONLY` blocks** until a writer appears. One
  request for one fifo inside the document root wedged the whole
  single-process server; `make test` hung instead of failing. `O_NONBLOCK`.
- **`open(2)` with `O_RDONLY` succeeds on a directory on Linux**, so the
  `index.html` fallback written behind an `errno == EISDIR` was unreachable
  and `/` returned 403.
- **`curl -I` writes the header block to `-o` as well as to `-D`**, so
  measuring the `-o` file to prove a HEAD response had no body was measuring
  121 bytes of headers.
- **`curl -H 'Name;'` removes a header** rather than sending an empty one, so
  the "empty If-Modified-Since is ignored" assertion was passing on a request
  that did not contain the field.
- **`curl` maps `-o` to URLs positionally**, so one `-o /dev/null` in front of
  two URLs sends the second body to stdout, where it lands in the middle of
  the `%{num_connects}` digits being parsed.
- **`$(printf '\r\n')` is `"\r"`.** Command substitution strips trailing
  newlines, so every raw request was sent with bare-CR line endings and the
  server correctly sat waiting for a terminator that never came.
- **A bare `wait` in the harness waits for the server too**, since it is a
  background job of the same shell. The suite hung until the outer timeout
  killed it, which is the one thing `make test` promises cannot happen.

## Files

```
httpd.c      the server, one file
Makefile     build, test, test-asan, clean
t/run.sh     the suite; prints "N passed, M failed"
t/raw.py     a deliberately incorrect HTTP client, for requests curl will not send
t/tmp/       scratch: document root, the 10MB fixture, the secret file. Not committed.
PLAN.md      contract, invariant, ranked oracles, non-goals, commit sequence
```

Everything the suite creates lives under `t/tmp/` inside this repository.
Nothing is written to `/tmp`, which is tmpfs here and does not survive a
reboot.

## Licence

GPL-3. See `LICENSE`.
