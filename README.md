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

A static file server is a path traversal sink. The request target is chosen
by whoever is talking to it and ends up in `open(2)`. One statement has to be
true, and the rest of this section is about how it is made true and how it is
proved:

> No request can cause a byte to be read from outside the document root.

### Three layers, because each one alone has a hole

1. Percent-decoding happens exactly once. `%2e%2e%2f` becomes `../` and is
   then caught by layer 2. `%252e%252e%252f` becomes the literal nine-byte
   segment `%2e%2e%2f`, a filename and no traversal at all, so the
   correct answer for the double-encoded form is 404, because no such file
   exists. Decoding in a loop until the string stops changing is the bug that
   makes double encoding work, so there is no loop.
2. A `..` segment is refused, not popped. Popping is what a normaliser
   does, and a normaliser has to be correct about every encoding of every
   separator in order to be safe. Refusing has to be correct about one string.
   Any segment beginning with `.` is refused as well, by the same
   no-dotfiles rule.
3. `realpath(3)` containment. The resolved path must still begin with the
   document root, which is itself `realpath`'d once at startup. This is the
   only layer that can see a symlink: there is nothing hostile in the string
   `/escape`.

### The oracle: a secret file outside the root

`t/run.sh` writes `SUPERSECRET-5f3a9c-DO-NOT-SERVE` into a file outside the
document root, puts a symlink to it inside the root, and puts a second
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

A symlink that stays inside the root is served (`serve. Symlink inside
root`), because it is a document and not an escape. Fifteen assertions for what
the resolver must still serve come before the refusals in the file, for the
reason that a resolver which refuses everything satisfies every refusal test
ever written.

### Request smuggling

Two refusals, both from RFC 9112:

- Content-Length together with Transfer-Encoding is 400, in both field
  orders. Section 6.1 permits resolving it in favour of Transfer-Encoding and
  6.3 says such a message "ought to be handled as an error". It is an error
  here, because one hop frames the message by one field and the next hop by
  the other.
- Whitespace before the colon in a header line is 400, as section 5.1
  requires. `Host : evil` is not a field named `Host ` and is not normalised
  into `Host`: it is a malformed line. An intermediary that trims the space
  and a server that does not now disagree about the Host of the request.

Also refused as framing errors: two conflicting `Content-Length` fields,
`Content-Length` as a comma list, signed, hex, empty or large enough to
overflow `strtoll`, obs-fold continuation lines, a bare CR or LF surviving
inside a field value, a NUL anywhere in the header section, and a missing or
duplicated `Host` on HTTP/1.1.

And the other half of smuggling: the request body is read and discarded
even for GET, because a body that is not read is not gone. It stays in the
socket and becomes the next request on a keep-alive connection. The assertion
`pipeline. Body is not a request` sends a request whose 39-byte body reads
`GET /sub/deep.txt HTTP/1.1...` and requires exactly one response.

### Mutation testing of the security property

Three mutants were built and run through the whole suite:

| Mutation | Verdict |
| --- | --- |
| delete the `realpath(3)` containment check | **caught**: 3 failures, including `deny: secret never served` with the secret in a body |
| delete both the containment check and the `..` refusal | **caught**: the secret is served with 200 |
| delete the `..` refusal alone | **SURVIVES**, all assertions pass |

The surviving mutant is honest and expected: layer 3 catches every `..` case
the suite can construct, because `realpath` either resolves outside the root
(403) or fails (404). Layer 2 is kept anyway, because it refuses before
touching the filesystem at all and because it makes the refusal independent of
`realpath(3)` being right. If you want a test that fails when layer 2 is
removed, it has to be one where `realpath` succeeds inside the root: the
stricter-than-necessary refusal of `/sub/../ok.txt`.

## Conditional requests

Three: `If-Modified-Since`, `If-None-Match` against a strong `ETag`, and
`If-Range`. Both 200 and 206 carry `Last-Modified` and `ETag`. A 304 carries
`Last-Modified` and `ETag`, no body, and no `Content-Length`.

### The tag

```
ETag: "32-7d2b11-6-6ad47b32.056711f4"
        dev  ino    sz  mtime s  mtime ns
```

`st_dev` and `st_ino` say which file; `st_size` and `st_mtim` say which
generation of it. The nanoseconds are the entire reason this header is
here. An HTTP-date carries one second, so `If-Modified-Since` cannot tell
two versions of a file written inside the same second apart, and an editor
saving twice or a build system rewriting an asset does that routinely.

The suite demonstrates the hole and then closes it, in four consecutive
assertions: one file, two contents of the same length, both mtimes set by
python to the same second and different nanoseconds, so the case does not
depend on winning a race against the wall clock.
`etag: by date, a same-second rewrite looks unchanged` asserts the 304,
because a 304 is the best a date-based conditional can do and the next
assertion means nothing without it. `etag: by tag, the same rewrite is a
200` and `etag: and the new bytes are what arrive` are the fix.

### The rules, and the one that is easiest to get backwards

RFC 9110 13.1.2 for the matching, 13.1.3 for the precedence, 13.2.2 for the
evaluation order, 15.4.5 for what a 304 must carry.

- `*` matches whenever a representation exists. On a file that does not
  exist the condition is false and the answer is the ordinary 404, not a
  304.
- The comparison is the **weak** one, which 13.1.2 requires for
  `If-None-Match` and not for `If-Match` or `If-Range`: `W/"x"` matches
  `"x"`. The tags generated here are always strong, so a `W/` can only have
  come from a cache that weakened one, and refusing to match it would turn
  every revalidation that cache makes into a full transfer.
- A comma list matches if any member does.
- An unparseable list is ignored and the answer is 200. Same rule as a
  malformed `If-Modified-Since`, and the opposite of this program's reflex
  everywhere else.
- `If-None-Match` present means `If-Modified-Since` is **ignored**, not
  combined with it. This is the one worth a paragraph. "Evaluate both and
  take either" is the natural implementation, it passes every other
  assertion in the section, and it fails in the direction that serves
  nothing: a client holding a stale tag and a recent date gets a 304 and
  keeps the stale copy. `etag: a stale tag beats a satisfied date` is the
  assertion, and the mutant that evaluates both fails it and nothing else.
- The precondition is evaluated before `Range`, so a matching tag on a
  range request is a 304 and not a 206.

### The oracle, and what it is missing

curl does the whole protocol dance in two assertions: `--etag-save` parses
the tag out of the 200 with curl's own parser and `--etag-compare` builds
the `If-None-Match` request from it, so neither the reading of the header
nor the writing of the request is ours. The remaining assertions send
explicit `-H 'If-None-Match: ...'` values and take curl's reported status.

**No second HTTP server is installed on this machine.** Checked, not
assumed: nginx, apache, lighttpd, thttpd, darkhttpd, caddy, busybox, ruby,
php, netcat and socat are all absent. Python's `http.server` is here and is
a second implementation, but `inspect.getsource` of it contains no
occurrence of `Range`, `Content-Range`, `Accept-Ranges`, `If-Range` or
`ETag`, so it implements none of this and cannot be asked whether a 206 is
right. It does handle `If-Modified-Since`, which `date(1)` already
cross-checks. `wget` is a second client and has no `If-None-Match` or
`If-Range` support of its own.

So unlike `Content-Type`, where `file(1)` answers the same question from the
content, there is no other implementation here to diff these answers
against: the authorities for the conditionals are curl, `cmp(1)` and the RFC
text. That is a weaker position than the rest of the suite is in, and it is
written down rather than papered over.

### Mutation testing of the conditionals

Eight mutants, each built and run through the whole suite. No survivors.

| Mutation | Verdict |
| --- | --- |
| compare the tag with `!=` instead of `==` | **caught**: 12 failures |
| emit a body and a `Content-Length` with the 304 | **caught**: 5, including `keep: 304 does not close` |
| drop the `ETag` from the 304 | **caught**: 1, `etag: the 304 repeats the ETag` |
| evaluate both conditionals and take either | **caught**: 1, `etag: a stale tag beats a satisfied date` |
| strong comparison: do not strip the `W/` | **caught**: 2 |
| drop the nanoseconds from the tag | **caught**: 3, all in the same-second block |
| ignore the `*` form | **caught**: 2 |
| drop the `ETag` from the 200 | **caught**: 13 failures and 2 skips |

Two rows are worth reading twice. The 304-with-a-body mutant was expected to
fail the two assertions that count the bytes after the header block; it also
failed `keep: 304 does not close`, which is curl noticing that the
connection had desynchronised and opening a second one. That is the
real-world consequence of the violation, caught by an assertion written
years of commits earlier for something else.

And the last row's two skips are the loud-skip path working as intended:
with no `ETag` in the 200, `curl --etag-save` writes an empty file, and the
suite says it could not make the assertion instead of passing it.


### If-Range, and the corruption it prevents

This is the one conditional here whose absence corrupts data rather than
producing a wrong status code. Measured against this server before the header
existed:

```
curl -r 0-999 /ifr.bin        1000 bytes of generation A
   (the file is rewritten: same length, different bytes)
curl -C - -o part /ifr.bin    206, 3000 bytes downloaded
part                          4000 bytes, 1000 of A followed by 3000 of B
```

A 206, a `Content-Length` equal to the bytes that followed, and a file that
is neither generation. Nothing in the exchange said so. `cmp(1)` is the only thing in the suite that can see it, and the
assertion `ifrange: without it, a changed file splices` requires the
corruption to be there, so that the two assertions after it mean something.

Neither `curl -C -` nor `wget -c` generates `If-Range` on its own. Both were
read off the wire rather than out of the manual, curl with `-v` and wget
against a server that echoed its request back, and both send a bare
`Range: bytes=N-`. So the splice above is what the two installed resume
clients do by default, and a server that cannot be told the representation
changed has no way to stop them.

#### The rules, and the two that differ from `If-None-Match`

RFC 9110 13.1.5, with 13.2.2 for where it sits in the order.

- An entity-tag or an HTTP-date, told apart by whether the first character is
  a `"`. A field that is neither takes the date path, fails to parse, and does
  not match.
- The entity-tag comparison is **strong**. `W/"x"` does not match `"x"` here,
  which is the opposite of the `If-None-Match` rule a few paragraphs up.
  Weak equivalence says two representations are interchangeable for caching;
  cutting a byte range out of one of them needs the bytes to be the same
  bytes. A weak validator must not be used for this field at all, and since
  `W/` fails the `"` test it reaches the date path and is rejected there.
- The date comparison is **exact**, not the "earlier than or equal to" of
  `If-Modified-Since`. A date later than the `Last-Modified` satisfies a 304
  and does not satisfy this.
- A validator that does not match means the `Range` field is ignored and the
  whole representation goes out with 200. Not 412, not 416. The field is
  ignored entirely rather than just its 206, so a stale validator in front of
  an unsatisfiable range is also a 200: checking `If-Range` after the range
  has been parsed answers 416 there, which tells the client its resume failed
  for a reason that is not true.
- `If-Range` with no `Range` is ignored. True here by construction, since
  nothing reads the field outside the block that needs a range.
- 13.2.2 evaluates it last, so a matching `If-None-Match` is still a 304 on a
  range request carrying a stale `If-Range`.

The strongness rule for dates is the part this server can only half satisfy,
and the half it cannot is a ceiling rather than an oversight. 13.1.5 requires
the condition to be false when the date is not a strong validator in
8.8.2.3's sense, which asks the origin server to know the representation did
not change twice inside the second the date names. `stat(2)` reports the last
write and not the history, so that is not deducible here. What is deducible
is the other direction: once the clock has left that second, nothing further
can be written inside it. So `mtime < now` is required, and a file written
during the current second is treated as having no strong date validator. A
client that wants a resume to be safe inside a one-second window has to use
the `ETag`, which is what the nanoseconds in it are for.

#### The oracle: curl does the resuming, cmp decides

`curl -C -` is the client this header exists for. It reads the length of the
local partial file, builds the `Range` from it and appends what arrives, so
the offset arithmetic a resume depends on is curl's and not ours. `cmp(1)`
then decides what the finished file is.

curl's own reaction to a declined resume is the part worth having. Sent a 200
where it asked for a 206, curl exits 33 with "HTTP server does not seem to
support byte ranges. Cannot resume." and writes nothing: the partial file on
disk is byte-identical to what it was, asserted with `cmp`. That exit code is
curl's verdict and not ours, and it is the whole value of the header. The
resume fails loudly instead of succeeding into a corrupt file.

Three assertions run end to end: the splice above, the same resume with the
validator the first attempt was given (exit 33, partial file untouched), and
a resume of the generation actually on disk, which completes to a file `cmp`
cannot distinguish from it.

#### Which branch each request took

An `If-Range` test whose requests do not carry `If-Range` passes vacuously,
and this suite has already been caught by a header curl did not send: the
"empty `If-Modified-Since` is ignored" assertion was green against a request
with no such field in it. So every header-level assertion goes through one
wrapper that reads curl's own trace of what it put on the wire and refuses to
make the assertion at all unless `If-Range` and `Range` are both there with a
value. The suite prints the counts and requires all four to be non-zero:

```
ifrange branches: tag honoured 2, tag ignored 5, date honoured 2, date ignored 4
```

Thirteen requests, each one confirmed on the wire and each paired with an
asserted status. Nine of the twenty-three assertions in the section are
"must not refuse" cases, which is the direction this program gets wrong by
reflex.

Four mutations of the harness, to find out what that gate is worth:

| Harness mutation | Verdict |
| --- | --- |
| drop the `If-Range` header from one asserted case | **caught**: `curl sent no If-Range value`, and the count drops to 4 |
| send no `If-Range` argument at all on a matching case | **caught**: same, count drops to 1 |
| delete one of the two date-honoured cases | **SURVIVES**: the branch is still reached, so the gate is still telling the truth |
| delete both, emptying that branch | **caught**: `ifrange: all four branches were reached`, date honoured 0 |

The survivor is the gate being exactly as strong as its claim and no
stronger. It says a branch was reached, so it fires when a branch is emptied
and not when an assertion is removed from a branch that still has one. An
exact count would catch that and would go red every time an assertion is
added, which is a worse trade.

#### Mutation testing of If-Range

Eleven mutants, each built and run through the whole suite. No survivors.

| Mutation | Verdict |
| --- | --- |
| strip `W/` before comparing, the `If-None-Match` rule | **caught**: 1, `the weak form of our own tag does not match` |
| reuse `inm_match`, so weak and comma-list forms both match | **caught**: 2 |
| date comparison `<=` instead of `==` | **caught**: 1, `a later date does not match either` |
| drop the strongness guard on the date | **caught**: 1, `a date whose second is not over is not strong` |
| ignore `If-Range` entirely, the behaviour before this commit | **caught**: 12 |
| a mismatch refuses with 416 instead of ignoring the `Range` | **caught**: 11 |
| check `If-Range` after `parse_range`, so a 416 outranks the ignore rule | **caught**: 1, `a stale tag over an unsatisfiable range is 200` |
| `If-Range` present suppresses the 304, inverting 13.2.2 | **caught**: 1, `a 304 beats both answers` |
| a tag that is a prefix of ours matches | **caught**: 1 |
| drop the `"` test, so every validator is read as a date | **caught**: 4 |
| accept any validator the date parser rejects | **caught**: 2 |

The two broad ones are worth separating, and the difference between their
failure sets was read off a diff rather than guessed. "Ignore `If-Range`
entirely" is the code as it stood before this commit and fails twelve
assertions. "Refuse with 416" fails eleven, and the twelfth is the one it
passes: `ifrange: and the partial file is untouched`. Both mutants are wrong
about exactly the same requests, and both fail the assertion that curl exits
33, so both are caught. But a wrong refusal and a wrong answer do different
damage downstream. A 416 leaves the client's partial file alone because curl
writes nothing for it either, while a 206 for a stale validator appends three
thousand bytes of the wrong generation onto it. Only one of the two mutants
corrupts a file on disk, and it is the one that answers rather than
refuses.


## The oracle

`curl` is the authority. Every assertion drives a real `curl` against a real
server on a real socket, and the thing asserted is the status code curl
reports, the header block curl saved, or the bytes curl wrote to a file.
Nothing in the suite inspects httpd's memory or trusts it about anything.

Four other outside authorities are used where curl cannot answer. The table
below lists five rows, and the first is curl itself, `raw.py` is ours, which
the section above says plainly, so it is not among them:

| Oracle | What it decides | Why it is independent |
| --- | --- | --- |
| `curl` | status codes, headers, bodies, `%{content_type}`, `%{num_connects}`, the `-C -` resume arithmetic and its exit 33 | a different program by other people implementing the same RFC |
| `cmp(1)` with `tail`/`head` | byte-for-byte file and range integrity | coreutils does the offset arithmetic, not us |
| `file(1)` | Content-Type for 4 fixtures | reads the file's **content**; httpd reads its **name** |
| `date(1)` | the `Last-Modified` value | formats the same mtime through different code |
| `/proc/PID/status` | SIGPIPE is ignored | the kernel's own view of the live process |
| `t/raw.py` | malformed requests | **ours**, and therefore the weakest, see below |

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

Not implemented at all

- TLS. No `https`. Put it behind something that does TLS, or do not.
- CGI, PHP, FastCGI, proxying, rewriting, redirects. Files only. There is
  not even a 301 from `/sub` to `/sub/`: both serve the same `index.html`,
  which is wrong in the strict sense that relative links in that document
  resolve differently, and is not fixed.
- Virtual hosting. `Host` is required on HTTP/1.1 and then ignored
  completely. Two names pointing here serve the same tree.
- Directory listings. A directory with no `index.html` is 403. A generated
  listing is a disclosure feature.
- `If-Unmodified-Since` and `If-Match`. `If-Modified-Since`,
  `If-None-Match` and `If-Range` are the three conditionals here. The two
  missing ones guard writes, and there is nothing here to write to: every
  method other than GET and HEAD is refused before a precondition could be
  evaluated.
- Compression. No `Content-Encoding`, no precompressed `.gz` lookup.
  `Accept-Encoding` is ignored.
- `Content-Type` charset. Never sent. A guessed charset is a claim about
  bytes nothing here has looked at, and a client told the wrong charset trusts
  it over its own detection.
- Caching headers. No `Cache-Control`, no `Expires`.
- Access logging. Nothing is written to stdout after the port line, and
  the suite asserts stderr stays empty.
- IPv6. `-a` takes an IPv4 literal. The socket is `AF_INET`.
- Methods other than GET and HEAD. Everything else is 405 with
  `Allow: GET, HEAD`, including methods the server has never heard of, where
  RFC 9110 would prefer 501. The distinction is not observable here, since
  nothing is implemented for any of them.

Implemented, with a ceiling (each one is a `shortcut:` comment in the
source naming its upgrade path)

- One process, one thread. One CPU's worth of throughput. The upgrade is
  `SO_REUSEPORT` plus `fork()`, which changes no parsing.
- Multi-range requests are refused with 416. A single range is fully
  supported in all three forms. `multipart/byteranges` needs a boundary
  generator, per-part headers and a second body pump. RFC 9110 14.2 would also
  permit ignoring the `Range` header and answering 200; 416 is the louder
  answer and it is a deliberate deviation.
- The MIME table is hard-coded, fifteen extensions. Not `/etc/mime.types`.
- The `ETag` is built from the inode, not from the bytes. It is a correct
  strong validator for one copy of one file on one filesystem, and it says
  nothing useful across machines: two servers behind one cache give the same
  file two different tags and the cache never gets a hit, and a file
  restored from a backup gets a new tag for identical content. The upgrade
  path is hashing the content, which costs a read of the whole file on every
  request.
- `realpath(3)` is a check on a path, so there is a TOCTOU window between
  it and `open(2)` in which a path component could be replaced by a symlink.
  Closing it means walking the path with `openat(2)` and `O_NOFOLLOW` one
  segment at a time. It needs a local attacker with write access *inside* the
  document root, who can already replace the file being served.
- ASan cannot see a one-past-the-end read of a request. `struct conn`
  holds the request in a fixed `char in[8192]`, and the connections live in
  one static array, so a hundred-byte request leaves about eight kilobytes of
  live allocation behind it and a read off the end of the request lands
  inside it. Measured rather than assumed: a planted
  `c->in[c->inlen]` read, built with `-fsanitize=address,undefined`, served a
  200 and produced no diagnostic at all. The same build does catch a planted
  read past a stack array (`stack-buffer-overflow` with a line number), which
  is why this was not obvious; the two buffer classes are not instrumented
  the same way, and it is the one holding untrusted input that is blind.
  There is no `make overread` gate here yet, because the fix is the one
  `jsonc` uses for its arena: parse out of an allocation sized to the bytes
  that actually arrived, behind a build flag, and run the suite both ways.
  Queued in `PLAN.md` with the measurement.
- The header section must fit in 8191 bytes (431 otherwise) and the
  request target in 2048 (414). A request body is read and discarded up to
  1MiB, over which it is 413.
- 256 connections, a compile-time constant. Past that, new connections sit
  in the listen backlog until a slot frees.
- A refusal always closes the connection, including 404 and 405. Those are
  answered before the body drainer has run, so the request's body may still be
  in the socket and keeping the connection open would mean reading it as the
  next request. Observable: curl opens a second connection after a 404
  (`keep: 404 closes`).
- A bare-LF line ending is not accepted anywhere. RFC 9112 2.2 permits a
  recipient to recognise a lone LF as a line terminator; this one requires
  CRLF, so an LF-only request is not malformed here, it simply never completes
  and is reaped by the request deadline.
- No `Server` header. Not a feature, just nothing to say.
- A closing connection lingers before `close(2)`: the write side is shut
  down and the rest of the client's request is read and discarded, bounded by
  `-t` and by 1MiB. Without it, `close(2)` on a socket with unread data makes
  the kernel send RST, which discards the response, so the client of a
  refused 2MB upload got "connection reset by peer" instead of the 413.

Slow loris: yes, it times out. The answer is a deadline on the *request*,
not a timeout on inactivity. A plain idle timeout does not stop a loris at
all, because one byte every N-1 seconds resets it forever. So while a request
is still arriving it must be complete within `-t` seconds of its first byte,
however busily the client dribbles, and past that it gets 408. While a
*response* is being written the deadline is the ordinary idle one measured
from the last byte that moved, because a 10MB body legitimately takes a while
and a slow reader is a customer, not an attack. `-t` defaults to 10
seconds. Eight assertions, including the two controls that a one-second server
still answers a normal request and one dripped at 5ms per byte.

## Where curl or the RFC contradicted an assumption

- curl normalises `%2e` away. `curl 'http://h/%2e%2e/secret.txt'`
  percent-decodes the `%2e`, removes the resulting dot segment, and sends
  `GET /secret.txt`, confirmed with `curl -v`. The traversal assertion was
  passing on a 404 for a file that does not exist, a green test for a request
  that was never made. `--path-as-is` is required. curl does *not* do
  this when the separator is also encoded (`%2e%2e%2f`), so only two of the ten
  encoded cases were affected.
- An invalid `If-Modified-Since` must be ignored, not refused. RFC 9110
  13.1.3 is explicit. Everywhere else in this program, something odd on the
  wire is a 400. Here it has to be a 200 with the full body.
- A malformed `Range` must be ignored. Only an unsatisfiable one is 416.
  RFC 9110 14.2. An unknown unit, a missing `=`, non-numeric or reversed
  positions all mean "send the whole thing". A `last-byte-pos` past the end of
  the file is neither. It is clamped.
- `close(2)` on a socket with unread data sends RST, and the RST discards
  any part of the response the client has not read yet. A 413 or a 400 to a
  client that is still uploading is therefore lost unless the server shuts
  down the write side and drains first. The suite reported this as an
  intermittent failure before it was understood as a defect.
- `open(2)` on a FIFO with `O_RDONLY` blocks until a writer appears. One
  request for one fifo inside the document root wedged the whole
  single-process server; `make test` hung instead of failing. `O_NONBLOCK`.
- `open(2)` with `O_RDONLY` succeeds on a directory on Linux, so the
  `index.html` fallback written behind an `errno == EISDIR` was unreachable
  and `/` returned 403.
- `curl -I` writes the header block to `-o` as well as to `-D`, so
  measuring the `-o` file to prove a HEAD response had no body was measuring
  121 bytes of headers.
- `curl -H 'Name;'` removes a header instead of sending an empty one, so
  the "empty If-Modified-Since is ignored" assertion was passing on a request
  that did not contain the field.
- `curl` maps `-o` to URLs positionally, so one `-o /dev/null` in front of
  two URLs sends the second body to stdout, where it lands in the middle of
  the `%{num_connects}` digits being parsed.
- `$(printf '\r\n')` is `"\r"`. Command substitution strips trailing
  newlines, so every raw request was sent with bare-CR line endings and the
  server correctly sat waiting for a terminator that never came.
- A bare `wait` in the harness waits for the server too, since it is a
  background job of the same shell. The suite hung until the outer timeout
  killed it, the one thing `make test` promises cannot happen.

## Files

```
httpd.c      the server, one file
Makefile     build, test, test-asan, clean
t/run.sh     the suite; prints "N passed, M failed, K skipped"
t/raw.py     a deliberately incorrect HTTP client, for requests curl will not send
t/tmp/       scratch: document root, the 10MB fixture, the secret file. Not committed.
PLAN.md      contract, invariant, ranked oracles, non-goals, commit sequence
```

Everything the suite creates lives under `t/tmp/` inside this repository.
Nothing is written to `/tmp`, which is tmpfs here and does not survive a
reboot.

## Licence

GPL-3. See `LICENSE`.
