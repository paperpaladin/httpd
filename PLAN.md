# PLAN

## Contract

```
httpd [-a addr] [-p port] [-r docroot] [-t idle_seconds]
```

A single-process HTTP/1.1 static file server in one C11 file, concurrent
through `poll(2)` and nothing else. It binds one TCP socket on `-a`
(default 127.0.0.1) and `-p` (default 0, meaning the kernel chooses), prints
`listening ADDR:PORT` on stdout and flushes it before the first `accept(2)`,
and then says nothing else for the rest of its life. The printed port is part
of the interface: the suite reads it, and a fixed port would collide with
anything else on the machine.

GET and HEAD, served from `-r` (default `.`). Everything else is 405 with
`Allow: GET, HEAD`.

On the wire:

- `Content-Length` on every response that has a body, always equal to the
  bytes that follow.
- `Content-Type` from the file extension, from a table of fifteen. No
  sniffing, no charset parameter.
- `Last-Modified` on every 200 and 206, in IMF-fixdate. `If-Modified-Since`
  in any of RFC 9110 5.6.7's three formats turns into 304 when the mtime is
  not newer. An unparseable value is ignored, not refused.
- A strong `ETag` on every 200 and 206, built from `st_dev`, `st_ino`,
  `st_size` and `st_mtim` to the nanosecond, and `If-None-Match` in all
  three forms: `*`, one tag, a comma list. The comparison is the weak one
  RFC 9110 13.1.2 requires, so `W/"x"` matches `"x"`. When `If-None-Match`
  is present `If-Modified-Since` is ignored entirely, per 13.1.3, and an
  unparseable list is ignored rather than refused. A 304 repeats the `ETag`
  and carries no body and no `Content-Length`.
- `Accept-Ranges: bytes`, and single byte ranges in all three forms:
  `bytes=a-b`, `bytes=a-`, `bytes=-n`: answered 206 with `Content-Range`.
  Unsatisfiable is 416 with `Content-Range: bytes */size`. Malformed is
  ignored and the whole representation is sent; a `last-byte-pos` past the end
  is clamped.
- HEAD gets byte-identical headers to GET, `Content-Length` included, and no
  body.
- Keep-alive by default on HTTP/1.1, off on HTTP/1.0 unless asked for, with
  pipelining. Request bodies: `Content-Length` or chunked, are read and
  discarded so the stream stays aligned.
- A directory serves `index.html` or 403. Never a listing.

Status codes are part of the contract because the suite asserts them: 200,
206, 304, 400, 403, 404, 405, 408, 413, 414, 416, 431, 501, 505.

## Hard invariant

**No request can cause a byte to be read from outside the document root, and
no request can make two parties disagree about where it ends.**

Two halves, and both are checked by something outside this program.

1. Containment. The request target is attacker-controlled and ends up in
   `open(2)`. Percent-decoding happens exactly once, so `%252e` is a filename
   and not a traversal; a `..` segment is refused, not popped; and
   `realpath(3)` of the result must still begin with the `realpath(3)` of the
   document root, the only check that can see a symlink. A secret
   file outside the root, a symlink to it inside the root, and a symlink to
   the parent directory inside the root are the oracle: 35 attacks each assert
   a refusing status code AND that the secret string is absent from the body,
   and every body the suite collects is grepped once at the end.
2. Framing. `Content-Length` with `Transfer-Encoding` is 400 in both
   orders; whitespace before a colon is 400; conflicting `Content-Length` is
   400, and the request body is drained even for GET, because a body left in
   the socket becomes the next request. The assertion that ties the two
   together sends one request whose body reads like a second request and
   requires exactly one response.

If either half fails the program is worthless. A static file server that can
be made to read `/etc/shadow` is a vulnerability with an HTTP interface, and
one that disagrees with its own proxy about message boundaries is a
vulnerability in everything in front of it.

## Oracle

Ranked by how little of each is ours.

1. `curl`. A different program, written by other people, implementing the
   same RFC. Every assertion in the suite is a real `curl` against a real
   socket, and the verdict is curl's reported status code, curl's saved header
   block, or the bytes curl wrote to a file. Two of its report fields are
   oracles nothing else here can replace: `%{content_type}` is curl's *parse*
   of the header, not a grep of our output, and `%{num_connects}` is
   curl's own count of TCP connections opened: the only way to assert
   keep-alive at all, since reuse and reconnection produce identical status
   codes. `--path-as-is` is required for the encoded-traversal cases, because
   curl normalises `%2e%2e/` away on the client side.

2. `cmp(1)`, with `tail(1)` and `head(1)`. Byte-for-byte integrity of a
   10MB body and of nineteen ranges within it. The slice is cut by coreutils,
   so the offset arithmetic the assertion depends on is not the offset
   arithmetic under test. 10MB is 160 trips through the 64KB output buffer,
   which makes this the only assertion that sees the partial-write pump.

3. `file(1)`, `date(1)`, and `/proc/PID/status`. Three narrow oracles that
   each answer a question curl cannot. `file --mime-type` reads the file's
   *content* where httpd reads its *name*, for four fixtures whose bytes
   really are what their extension claims. `date(1)` formats the same mtime
   from the same `stat(2)` through different code, so agreement about
   `Last-Modified` is evidence about the format and the timezone,
   not about our `strftime` being self-consistent. `/proc/PID/status` is the
   kernel's own view of the live process, and bit 12 of `SigIgn` is the only
   way to distinguish "ignores SIGPIPE" from "has not been sent one yet".

4. `t/raw.py`. The weakest, and necessary. curl is a correct client: it
   will not put a space before a colon, send two conflicting
   `Content-Length` fields, write an 83-digit chunk size, or dribble a request
   line one byte per second. These assertions are printed with a `raw:` prefix
   to mark that the request is ours even though the verdict is httpd's.

5. Mutation testing, by hand, recorded in README.md. Not an oracle for the
   program but for the suite. Fourteen mutants so far: deleting the `realpath`
   containment check, deleting it together with the `..` refusal, deleting the
   `..` refusal alone (survives, and the README says why), skewing the `pread`
   offset by one, reverting the request deadline to a plain idle timeout,
   planting a stack overread for `make test-asan`, and eight against
   `If-None-Match` and the ETag. Each one was built and run through the whole
   suite and the verdict written down.

## Non-goals

- TLS. Not "later": not here. A TLS stack in the same file as a
  hand-written HTTP parser is two attack surfaces sharing a buffer.
- CGI, FastCGI, proxying, rewriting, redirects. Files only. The missing
  301 from `/sub` to `/sub/` is documented, not fixed.
- Virtual hosting. `Host` is required on HTTP/1.1 and then ignored.
- Directory listings. 403. A generated listing is a disclosure feature,
  and the one thing a static server should never invent.
- Being nginx. No config file, no modules, no `Cache-Control`, no
  compression, no access log, no IPv6, no `sendfile(2)`. There is an `ETag`,
  because an entity-tag is a correctness fix and not a tuning knob.
- A second parsing path. No fallback parser, no lenient mode, no
  `--allow-bare-lf`. Two parsers for one grammar is how smuggling happens
  inside a single program.
- Normalising a hostile path instead of refusing it. A normaliser has to
  be right about every encoding of every separator. A refusal has to be right
  about one string.
- Threads or processes. One `poll(2)` loop. Named as a ceiling, with
  `SO_REUSEPORT` plus `fork()` as the upgrade path.
- A library. One program, one job.

## Commit sequence

Eighteen commits, every one of which builds and passes the assertions that
existed at that point.

- [x] `Makefile`, `LICENSE`, `.gitignore`, and `httpd.c` with the listening
      socket, the `poll(2)` loop and the connection state machine.
      why: four decisions here cannot be changed cheaply afterwards: the
      ephemeral port read back with `getsockname(2)`, every socket
      non-blocking, `SIGPIPE` ignored before anything else happens, and
      connections processed before `accept(2)` and backwards so that
      `revents` still maps to the connection it was polled for. The last one
      was written the other two ways first and both are silent.
- [x] `t/run.sh`: curl as the oracle, before any HTTP parsing exists.
      why: landing the harness second means every commit after it is gated by
      an outside program, not by review. The `port: announced port
      accepts` and `server: still running` assertions are there because a
      suite whose server died reports a row of connection failures as
      ordinary assertion failures and buries the cause.
- [x] Request line parsing, and `t/raw.py` as the incorrect client.
      why: RFC 9112 section 3 is one line of grammar and most of the refusals
      in the program. Found two harness bugs immediately, including
      `$(printf '\r\n')` being `"\r"`.
- [x] Header parsing, and the two request smuggling refusals.
      why: fifteen of the twenty assertions are refusals and four are the
      cases next to them that must still be accepted, because a parser that
      rejects everything passes every refusal test ever written. Found that
      `GET / HTTP/1.1` with no header line skipped the whole header parser
      and with it the Host requirement.
- [x] The path resolver: three layers of refusal, and the secret file outside
      the root.
      why: the security property gets its own commit. Also the commit that
      found `open(2)` blocking on a FIFO, `O_RDONLY` succeeding on a
      directory, and curl normalising `%2e%2e/` away on the client side.
- [x] Byte-for-byte integrity: a 10MB body, `cmp(1)` as the oracle.
      why: 160 trips through the output buffer is the only thing that
      exercises the partial-write pump, and a checksum computed by the same
      program that served the bytes proves nothing.
- [x] `Content-Type` from the extension, cross-checked against `file(1)`.
      why: `file(1)` answers the same question from the content, and that is the
      only independent check available for a lookup table.
- [x] HEAD: identical headers, not one body byte.
      why: "identical" is the part that gets implemented wrongly.
      `Content-Length` must still be the length a GET would have sent.
- [x] Conditional GET: `Last-Modified`, `If-Modified-Since`, three date
      formats.
      why: the one place in this program where something odd on the wire must
      be ignored, not refused, and the comparison has to be `<=`
      because an HTTP-date carries one second of resolution.
- [x] Byte ranges: 206, `Content-Range`, and the difference between ignoring
      and 416.
      why: nineteen boundaries around the buffer seam and both ends of the
      file, and four assertions in each direction for the ignore-versus-416
      rule, which is easy to get backwards.
- [x] Request bodies: `Content-Length` and chunked, read and discarded.
      why: a body that is not read is not gone. It becomes the next request on
      a keep-alive connection, the other half of smuggling.
- [x] Keep-alive and pipelining, with `num_connects` as the oracle.
      why: "the connection stayed open" and "the connection was reopened and
      nobody noticed" produce identical status codes.
- [x] Concurrency, mid-response disconnects, and SIGPIPE.
      why: none of these are visible in a status code; the question each one
      asks is whether the server is still there afterwards. Found a bare
      `wait` in the harness that waited for the server itself.
- [x] Slow loris: a deadline on the request, not a timeout on inactivity.
      why: an idle timeout does not stop a loris at all, because one byte
      every N-1 seconds resets it forever. Watched the assertion fail against
      the idle-timeout version.
- [x] `make test-asan`, and an orderly exit so LeakSanitizer can run.
      why: every byte of a request is untrusted input parsed with pointer
      arithmetic over fixed buffers. A server that is always killed outright
      is a server whose leak check can never fire.
- [x] `README.md`.
      why: the "what does not work" list is longer than everything else in it,
      and the attack-to-assertion table is the part someone needs in order to
      check any security claim in it against one grep.
- [x] `PLAN.md`.
      why: the contract, the ranked oracles and the forward order belong in a
      different document from the transcript.
- [x] Lingering close.
      why: two intermittent failures in a clean run, and the first was a real
      defect being reported as flakiness. `close(2)` on a socket with unread
      data makes the kernel send RST, which discards the response, so every
      refused upload reached its client as "connection reset", not as
      the status code explaining why.

### Milestone 1: close the gaps that cost nothing conceptually

- [x] `If-None-Match` and a strong ETag built from `st_dev`, `st_ino`,
      `st_size` and `st_mtim` including nanoseconds.
      why: `If-Modified-Since` has one second of resolution, so a file
      rewritten twice in the same second is served stale to every client that
      asks conditionally. That is a correctness hole the suite can demonstrate
      today and cannot fix, and the oracle is immediate: curl's `--etag-save`
      and `--etag-compare` do the whole protocol dance from the other side.
      done: 28 assertions, 230 -> 258. The hole is now demonstrated and then
            closed in four consecutive assertions: one file written twice with
            python setting both mtimes to the same second and different
            nanoseconds, where the date-based conditional answers 304 with
            the old bytes still cached and the tag-based one answers 200 with
            the new bytes, and `Last-Modified` is asserted not to have moved.
            curl does the protocol dance itself in two of them, parsing the
            tag out of the 200 with `--etag-save` and building the request
            with `--etag-compare`.
            RFC 9110 13.1.3 was the rule most likely to be got wrong and has
            its own pair: `If-None-Match` present means `If-Modified-Since` is
            IGNORED, not combined, so a stale tag with a satisfied date is a
            200. "Evaluate both and take either" is the natural wrong version
            and it survives every other assertion in the section.
            Eight mutants, all caught. No second HTTP server is installed on
            this machine, so curl and the RFC are the whole oracle for this
            one and the README says so.
- [ ] `If-Range`, so a resumed download of a file that changed restarts
      instead of splicing two generations together.
      why: this is a data-corruption bug in the one feature people use
      ranges for. `curl -C -` on a file modified between attempts is the
      test, and it currently produces a corrupt result that cmp(1) can see.
- [ ] A 301 from `/sub` to `/sub/`.
      why: the README documents serving both as the same `index.html` and
      admits relative links in that document resolve differently. curl's
      `-L` plus `%{redirect_url}` is the oracle, and it is five lines.
- [ ] `multipart/byteranges` for multi-range requests.
      why: the only RFC feature currently refused with a status code that the
      RFC does not sanction for that case. `curl --range 0-1,5-6` parses the
      multipart body itself, so the oracle exists and is in use already.
- [ ] Accept a bare LF as a line terminator, behind a flag that defaults off,
      and assert that the default still refuses it.
      why: RFC 9112 2.2 permits recognising it, the README lists refusing it
      as a ceiling, and an LF-only request currently hangs until the request
      deadline instead of being answered. The interesting assertion is the
      one that the lenient mode and the strict mode disagree.

### Milestone 2: oracles the current suite cannot reach

- [ ] A fuzzer over the request parser, seeded with every fixture in
      `t/run.sh`, under ASan and UBSan, with a `--parse FILE` mode so the
      parser can be driven without a socket.
      why: a hundred hand-written malformed requests cover the cases that were
      thought of. The parser is small enough that a few million mutations
      would be a stronger statement than any list, and `--parse` would also
      make the parser testable without the 100-connection machinery. This is
      the single largest gap in the suite.
- [ ] A second HTTP client as a differential: `wget`, `nghttp`, or python's
      `http.client`, run against the same fixtures.
      why: every positive assertion here is curl's reading of the response. A
      header curl is lenient about, and curl is lenient about several, is
      a header this suite cannot see is wrong.
- [ ] A real intermediary in front of it for the smuggling cases: two
      instances with one proxying to the other.
      why: the smuggling refusals are justified by what a *next hop* would do
      and asserted only against this server's own status code. Putting a
      second hop behind it turns "we refuse this" into "the pair cannot be
      desynchronised".
- [ ] `strace -c` or `/proc/PID/io` in the suite, asserting that serving a
      10MB file does not read it twice.
      why: the pump's efficiency is currently unmeasured, and the obvious
      regression, re-reading from offset zero on every refill, was caught
      by `cmp` only because the bytes came out wrong. A version that is merely
      slow would pass.
- [ ] Run the suite with `-t 0` and with `MAXCONN` lowered to 4, to reach the
      backlog and reaping paths the machine never makes happen.
      why: the `nconn == MAXCONN` branch that stops polling the listener has
      never executed in a test run.
