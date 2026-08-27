#!/bin/sh
# The oracle. Every assertion below is made by driving a real curl(1) against
# a real httpd listening on a real socket, and the thing asserted is the
# status line, the headers or the response bytes that curl reports. Nothing
# here inspects httpd's internal state.
#
# curl is the authority because it is a different program, written by other
# people, that implements the same RFC. Where curl cannot construct a request
# -- because it is malformed in exactly the way that is interesting -- t/raw.py
# sends the bytes verbatim; those cases are marked `raw:` and are weaker
# oracles, because the request is ours even though the verdict is httpd's.
#
# Nothing in here may hang. Every curl gets --max-time, the server is killed
# from a trap on EXIT, and the harness never waits on a read without a bound.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
HTTPD="${1:-$ROOT/httpd}"
TD="$ROOT/t/tmp"             # scratch, under our own repo, never /tmp
MT=10                        # --max-time for every curl, seconds

pass=0; fail=0; skip=0

ok()    { pass=$((pass + 1)); printf 'ok    %s\n' "$1"; }
bad()   { fail=$((fail + 1)); printf 'FAIL  %s\n' "$1"
          shift; printf '%s\n' "$@" | sed 's/^/      | /'; }
skipt() { skip=$((skip + 1)); printf 'skip  %s  (%s)\n' "$1" "$2"; }

[ -x "$HTTPD" ] || { echo "run 'make' first" >&2; exit 2; }

rm -rf "$TD"; mkdir -p "$TD" || exit 2
: >"$TD/allbodies"

# ---------------------------------------------------------------------------
# the fixture: a document root, and a secret OUTSIDE it
#
# The secret file is the point. Every traversal assertion checks the status
# code AND greps the response body for this string, because a 200 with the
# wrong body and a 403 with the right one are both failures, and only one of
# them is visible in the status.
# ---------------------------------------------------------------------------
R="$TD/root"
SECRET='SUPERSECRET-5f3a9c-DO-NOT-SERVE'

mkdir -p "$R/sub" "$R/nodir" "$R/.git"
printf '%s\n' "$SECRET" > "$TD/secret.txt"
printf '<h1>root index</h1>\n'  > "$R/index.html"
printf 'plain text ok\n'         > "$R/ok.txt"
printf '<h1>sub index</h1>\n'    > "$R/sub/index.html"
printf 'deep\n'                  > "$R/sub/deep.txt"
printf 'dotfile body\n'          > "$R/.hidden"
printf 'dotdir body\n'           > "$R/.git/config"
ln -s "$TD/secret.txt" "$R/escape"      # symlink out of the root, readable
ln -s "$TD"            "$R/escapedir"   # symlink to the directory above it
ln -s ok.txt           "$R/inside"      # symlink that stays inside: allowed
mkfifo "$R/fifo" 2>/dev/null || true

# 10MB of deterministic pseudo-random bytes: every byte value, no structure,
# and reproducible so a failure can be looked at twice. This is the file the
# byte-for-byte assertions use, and it is far larger than the 64KB output
# buffer, so serving it has to survive dozens of partial writes.
BIG="$R/big.bin"
BIGSZ=10485760
python3 - "$BIG" "$BIGSZ" <<'PYBIG'
import random, sys
random.seed(20261009)
with open(sys.argv[1], "wb") as f:
    f.write(bytes(random.getrandbits(8) for _ in range(int(sys.argv[2]))))
PYBIG

# Typed fixtures whose CONTENT matches their extension, so file(1) can be
# asked the same question from the other side.
python3 - "$R" <<'PYTYPES'
import base64, sys, os
r = sys.argv[1]
png = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFAAH/"
    "q842iQAAAABJRU5ErkJggg==")
open(os.path.join(r, "a.png"), "wb").write(png)
open(os.path.join(r, "a.gif"), "wb").write(
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff"
    b"!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01"
    b"\x00\x00\x02\x02D\x01\x00;")
open(os.path.join(r, "a.pdf"), "wb").write(
    b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n")
open(os.path.join(r, "a.html"), "w").write(
    "<!doctype html>\n<html><head><title>t</title></head><body>hi</body></html>\n")
open(os.path.join(r, "a.css"), "w").write("body { color: red }\n")
open(os.path.join(r, "a.js"), "w").write("export const a = 1;\n")
open(os.path.join(r, "a.json"), "w").write('{"a": 1}\n')
open(os.path.join(r, "a.svg"), "w").write(
    '<svg xmlns="http://www.w3.org/2000/svg"/>\n')
open(os.path.join(r, "a.unknownext"), "w").write("mystery\n")
open(os.path.join(r, "noextension"), "w").write("mystery\n")
open(os.path.join(r, "a.HTML"), "w").write("<html>upper</html>\n")
open(os.path.join(r, "empty.txt"), "w").write("")
PYTYPES

# ---------------------------------------------------------------------------
# the server under test
# ---------------------------------------------------------------------------
"$HTTPD" -r "$R" -t 5 >"$TD/port" 2>"$TD/log" &
SRV=$!
# The trap is the reason `make test` cannot leave a server behind, and it is
# installed before the first assertion rather than after.
trap 'kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null' EXIT INT TERM

PORT=
i=0
while [ "$i" -lt 100 ]; do
	PORT=$(sed -n 's/^listening [0-9.]*:\([0-9][0-9]*\)$/\1/p' "$TD/port")
	[ -n "$PORT" ] && break
	sleep 0.05
	i=$((i + 1))
done
if [ -z "$PORT" ]; then
	echo "httpd never announced a port; its stderr was:" >&2
	cat "$TD/log" >&2
	exit 2
fi
U="http://127.0.0.1:$PORT"
echo "httpd on 127.0.0.1:$PORT  (curl $(curl --version | sed -n '1s/curl \([^ ]*\).*/\1/p'))"
echo

# ---------------------------------------------------------------------------
# fetch PATH [curl args...]  ->  $TD/h headers, $TD/b body, $ST status code
# ---------------------------------------------------------------------------
fetch() {
	_p=$1; shift
	ST=$(curl --http1.1 -sS --max-time "$MT" \
	          -o "$TD/b" -D "$TD/h" -w '%{http_code}' \
	          "$@" "$U$_p" 2>"$TD/curlerr") || ST="curl-exit-$?"
	# Every byte of every response body this suite has ever received,
	# in one file. The secret-file assertion at the end of section 5
	# greps THIS, not just the last response -- otherwise it is an
	# assertion about one request that happened to be refused.
	cat "$TD/b" >>"$TD/allbodies" 2>/dev/null
}

# tstatus NAME WANT PATH [curl args...] -- WANT may list alternatives
tstatus() {
	_n=$1; _w=$2; shift 2
	fetch "$@"
	case " $_w " in
	*" $ST "*) ok "$_n" ;;
	*) bad "$_n" "want status $_w, got $ST" "$(cat "$TD/curlerr")" ;;
	esac
}

# terr NAME CODE REASON PATH [curl args...] -- the whole refusal, not just
# the three digits.
#
# Every refusal assertion in this suite checked the status code and nothing
# else. Stripping the reason phrase, the Content-Type and the entire body from
# `reply()` -- so each of 400, 403, 404, 405, 408, 413, 414, 431, 501 and 505
# went out as "HTTP/1.1 400 \r\nDate: ...\r\nContent-Length: 0\r\n\r\n"
# with no body at all -- left 226 passed, 0 failed. Successful responses are
# verified byte for byte (tbody, cmp on the 10MB fixture, cmp on 18 ranges);
# the refusals, which is where the security and RFC 9112 claims live, were
# three digits deep.
#
# reply() emits "CODE reason\n" as a text/plain body, so that is what this
# asserts, along with the reason phrase appearing in the status line and a
# Content-Length matching the body it sent.
terr() {
	_n=$1; _c=$2; _r=$3; shift 3
	fetch "$@"
	if [ "$ST" != "$_c" ]; then
		bad "$_n" "want status $_c, got $ST" "$(cat "$TD/curlerr")"
		return
	fi
	_want="$_c $_r"
	_body=$(cat "$TD/b")
	_clen=$(sed -n 's/^[Cc]ontent-[Ll]ength: *\([0-9]*\).*/\1/p' "$TD/h" | tr -d '\r')
	_ctype=$(sed -n 's/^[Cc]ontent-[Tt]ype: *//p' "$TD/h" | tr -d '\r')
	if [ "$_body" != "$_want" ]; then
		bad "$_n" "body is [$_body], want [$_want]"
	elif [ "$_clen" != "$((${#_want} + 1))" ]; then
		bad "$_n" "Content-Length is [$_clen], want $((${#_want} + 1))"
	elif [ "$_ctype" != "text/plain" ]; then
		bad "$_n" "Content-Type is [$_ctype], want text/plain"
	else
		ok "$_n"
	fi
}

# tbody NAME WANT-EXACT PATH [curl args...]
tbody() {
	_n=$1; _w=$2; shift 2
	fetch "$@"
	_g=$(cat "$TD/b")
	if [ "$_g" = "$_w" ]; then ok "$_n"
	else bad "$_n" "want body [$_w], got [$_g]"; fi
}

# thdr NAME REGEX PATH [curl args...] -- REGEX matched against the header block
thdr() {
	_n=$1; _r=$2; shift 2
	fetch "$@"
	if grep -qi "$_r" "$TD/h"; then ok "$_n"
	else bad "$_n" "no header matched /$_r/" "$(cat "$TD/h")"; fi
}

# ---------------------------------------------------------------------------
# raw REQUEST [raw.py args...]  ->  $TD/raw, $RST status code
# For requests curl is too correct to construct. Weaker than curl as an
# oracle -- the bytes are ours -- but the verdict is still httpd's.
# ---------------------------------------------------------------------------
raw() {
	_q=$1; shift
	# %b, so the request bytes can be written with \r\n escapes. $(printf)
	# cannot carry a trailing CRLF: command substitution strips it, which
	# silently turned every raw request into a bare-CR request once.
	printf '%b' "$_q" | python3 "$ROOT/t/raw.py" "$PORT" "$@" \
	        >"$TD/raw" 2>"$TD/rawerr"
	cat "$TD/raw" >>"$TD/allbodies" 2>/dev/null
	RST=$(sed -n '1s|^HTTP/1\.[01] \([0-9][0-9]*\).*|\1|p' "$TD/raw" \
	      | tr -d '\r')
}

# traw NAME WANT REQUEST [raw.py args...] -- WANT may list alternatives
traw() {
	_n=$1; _w=$2; _q=$3; shift 3
	raw "$_q" "$@"
	case " $_w " in
	*" $RST "*) ok "raw: $_n" ;;
	*) bad "raw: $_n" "want status $_w, got [$RST]" \
	       "$(head -c 200 "$TD/raw")" "$(cat "$TD/rawerr")" ;;
	esac
}

# ---------------------------------------------------------------------------
# 1. the socket is there, and it speaks HTTP/1.1
# ---------------------------------------------------------------------------
tstatus 'root: 200'              200 /
thdr    'root: has Date'         '^Date: [A-Z][a-z][a-z], ' /
thdr    'root: has Content-Length' '^Content-Length: [0-9]'  /

# The announced port is the port it is actually listening on -- otherwise
# every assertion above would be against some other process.
#
# This was `[ "$ST" != "curl-exit-7" ]`, which passes on anything that is not
# "connection refused": a 404, a 500, a timeout -- and on curl being absent
# altogether, where $ST is "curl-exit-127". Removing curl from PATH gave 147
# failures and this assertion was among the 79 that still passed, which is the
# one circumstance in which it means nothing at all. $ST here is the status
# from the immediately preceding `thdr ... /` request, so 200 is the answer
# and anything else wants explaining.
if [ "$ST" = 200 ]; then ok 'port: announced port accepts'
else bad 'port: announced port accepts' "GET / on the announced port gave $ST"; fi

# ---------------------------------------------------------------------------
# 2. the request line (RFC 9112 section 3)
# ---------------------------------------------------------------------------
tstatus 'method: POST is 405'     405 / -X POST
thdr    'method: 405 has Allow'   '^Allow: GET, HEAD' / -X POST
tstatus 'method: unknown is 405'  405 / -X FROBNICATE
tstatus 'version: HTTP/1.0 ok'    200 / --http1.0

# Exactly one SP between the three fields. Being generous here is one of the
# two classic request smuggling primitives: a server that accepts
# "GET  /x HTTP/1.1" and a proxy that does not disagree about the target.
traw 'two spaces after method'    400 "GET  / HTTP/1.1\r\nHost: x\r\n\r\n"
traw 'leading space'              400 " GET / HTTP/1.1\r\nHost: x\r\n\r\n"
traw 'tab instead of space'       400 "GET\t/ HTTP/1.1\r\n\r\n"
traw 'no version (HTTP/0.9)'      400 "GET /\r\n\r\n"
traw 'version not HTTP/'          400 "GET / FTP/1.1\r\nHost: x\r\n\r\n"
traw 'version HTTP/1.1x'          400 "GET / HTTP/1.1x\r\nHost: x\r\n\r\n"
traw 'version HTTP/11'            400 "GET / HTTP/11\r\nHost: x\r\n\r\n"
traw 'version HTTP/2.0'           505 "GET / HTTP/2.0\r\nHost: x\r\n\r\n"
traw 'version HTTP/1.9'           505 "GET / HTTP/1.9\r\nHost: x\r\n\r\n"
traw 'method with a bad char'     400 "GE{T} / HTTP/1.1\r\nHost: x\r\n\r\n"
traw 'empty method'               400 " / HTTP/1.1\r\nHost: x\r\n\r\n"

# An over-long request line must be refused by the code, not by the stack.
# 414 is the RFC 9110 code for exactly this; a header *section* that overflows
# the buffer is 431.
#
# These used to accept '414 431 400' and '431 400', on the reasoning that the
# assertion is about refusing rather than about which refusal. But PLAN.md
# lists both codes as part of the contract and httpd really answers them --
# measured, 414 and 431 -- so collapsing `return 414` and `return 431` to 400
# in httpd.c left the suite green about a contract it had stopped meeting.
# Pinned, and checked all the way through the body.
LONG=$(python3 -c 'print("a" * 5000)')
terr 'reqline: over-long target is 414' 414 'URI Too Long' "/$LONG"
MANY=""
i=0
while [ "$i" -lt 200 ]; do
	MANY="$MANY -H X-Pad-$i:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	i=$((i + 1))
done
# shellcheck disable=SC2086
terr 'reqline: over-long header section is 431' 431 'Request Header Fields Too Large' / $MANY

# ---------------------------------------------------------------------------
# 3. the header section, and the two request smuggling primitives
# ---------------------------------------------------------------------------
# curl can be talked into some of these, and where it can, it is the better
# oracle: the bytes on the wire are then not ours.
tstatus 'hdr: space before colon'  400 / -H 'Host : evil'
tstatus 'hdr: CL and TE together'  400 / -H 'Transfer-Encoding: chunked' \
                                          -H 'Content-Length: 0'
tstatus 'hdr: TE gzip is 501'      501 / -H 'Transfer-Encoding: gzip'

traw 'space before colon'       400 "GET / HTTP/1.1\r\nHost : x\r\n\r\n"
traw 'tab before colon'         400 "GET / HTTP/1.1\r\nHost\t: x\r\n\r\n"
traw 'no colon at all'          400 "GET / HTTP/1.1\r\nHost: x\r\nJustWords\r\n\r\n"
traw 'empty field name'         400 "GET / HTTP/1.1\r\nHost: x\r\n: v\r\n\r\n"
traw 'obs-fold continuation'    400 "GET / HTTP/1.1\r\nHost: x\r\nX: a\r\n b\r\n\r\n"
traw 'missing Host'             400 "GET / HTTP/1.1\r\n\r\n"
traw 'two Host fields'          400 "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"

# RFC 9112 6.1 and 6.3: a message with both framings is framed one way by
# this hop and the other way by the next one. That is the whole of request
# smuggling, and it is refused rather than resolved.
traw 'CL + TE: chunked'         400 \
	"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n"
traw 'TE: chunked + CL (order)' 400 \
	"GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n"
traw 'two conflicting CL'       400 \
	"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\n"
traw 'CL as a comma list'       400 \
	"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 0, 0\r\n\r\n"
traw 'negative CL'              400 \
	"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n"
traw 'signed CL'                400 \
	"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: +1\r\n\r\n"
traw 'hex CL'                   400 \
	"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 0x10\r\n\r\n"
traw 'CL that overflows'        400 \
	"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999999999999999\r\n\r\n"
traw 'empty CL'                 400 \
	"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: \r\n\r\n"

# ... and the cases next to them that must NOT be refused, because a parser
# that rejects everything also passes every refusal assertion above.
traw 'two identical CL is ok'   200 \
	"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n"
traw 'odd OWS round the value'  200 \
	"GET / HTTP/1.1\r\nHost:    x\t \r\nContent-Length:  0 \r\n\r\n"
traw 'lower-case field names'   200 "GET / HTTP/1.1\r\nhOsT: x\r\n\r\n"
traw 'unknown fields ignored'   200 \
	"GET / HTTP/1.1\r\nHost: x\r\nX-Whatever: ~!#\$%&'*+-.^_\`|\r\n\r\n"

# ---------------------------------------------------------------------------
# 4. the path resolver: what it serves
#
# These come first. A resolver that refuses everything satisfies every
# assertion in section 5, so the refusals only mean something next to the
# requests that must succeed.
# ---------------------------------------------------------------------------
tbody 'serve: / is index.html'       '<h1>root index</h1>' /
tbody 'serve: /index.html'           '<h1>root index</h1>' /index.html
tbody 'serve: /ok.txt'               'plain text ok'       /ok.txt
tbody 'serve: /sub/ is sub index'    '<h1>sub index</h1>'  /sub/
tbody 'serve: /sub (no slash)'       '<h1>sub index</h1>'  /sub
tbody 'serve: /sub/deep.txt'         'deep'                /sub/deep.txt
tbody 'serve: "." segments skipped'  'plain text ok'       /./ok.txt --path-as-is
tbody 'serve: empty segments'        'deep'                /sub//deep.txt --path-as-is
tbody 'serve: query string ignored'  'plain text ok'       '/ok.txt?a=b&c=d'
tbody 'serve: %6f%6b decoded'        'plain text ok'       /%6fk.txt
# A symlink that stays inside the root is a document, not an escape.
tbody 'serve: symlink inside root'   'plain text ok'       /inside
tstatus 'serve: missing file is 404' 404 /nope.txt
tstatus 'serve: missing dir is 404'  404 /nope/nope.txt
tstatus 'serve: dir with no index'   403 /nodir/
tstatus 'serve: a fifo is not a doc' 403 /fifo

# ---------------------------------------------------------------------------
# 5. the path resolver: what it refuses
#
# THE security property. Each case asserts a refusing status code and that
# the secret string is nowhere in the response body. --path-as-is is what
# stops curl from normalising "/../" away on the client side, so the bytes
# that reach httpd are the bytes written here.
# ---------------------------------------------------------------------------
# tdeny NAME WANT PATH [curl args...]
tdeny() {
	_n=$1; _w=$2; shift 2
	fetch "$@"
	case " $_w " in
	*" $ST "*) ;;
	*) bad "deny: $_n" "want status $_w, got $ST"; return ;;
	esac
	if grep -q "$SECRET" "$TD/b" 2>/dev/null; then
		bad "deny: $_n" "status $ST but the SECRET was in the body!" \
		    "$(head -c 200 "$TD/b")"
	else
		ok "deny: $_n"
	fi
}

tdeny 'dot-dot'                403 /../secret.txt            --path-as-is
tdeny 'dot-dot twice'          403 /../../etc/passwd         --path-as-is
tdeny 'dot-dot after a dir'    403 /sub/../../secret.txt     --path-as-is
tdeny 'dot then dot-dot'       403 /./../secret.txt          --path-as-is
tdeny 'dot-dot trailing'       403 /sub/..                   --path-as-is
# curl itself percent-decodes %2e and removes the dot segment, sending
# "GET /secret.txt": verified with curl -v. So --path-as-is is required for
# the encoded form to reach httpd at all, and without it this assertion was
# passing on a 404 for a file that does not exist -- a green test for a
# request that was never made.
tdeny 'encoded dot-dot'        403 /%2e%2e/secret.txt --path-as-is
tdeny 'encoded dot-dot-slash'  403 /%2e%2e%2fsecret.txt
tdeny 'half-encoded'           403 /..%2fsecret.txt
tdeny 'upper-case hex'         403 /%2E%2E%2Fsecret.txt
tdeny 'encoded dot-dot deep'   403 /sub/%2e%2e/%2e%2e/secret.txt --path-as-is
# Double encoding must NOT be decoded twice. "%252e" decodes once to "%2e",
# which is a filename character. 404 is the correct answer: there is no file
# called "%2e%2e%2fsecret.txt" in the root. A 200 here would mean the
# decoder loops.
tdeny 'double-encoded'         404 /%252e%252e%252fsecret.txt
tdeny 'triple-encoded'         404 /%25252e%25252e%25252fsecret.txt
tdeny 'four dots'              403 /....//secret.txt         --path-as-is
tdeny 'dot-dot semicolon'      403 '/..;/secret.txt'         --path-as-is
tdeny 'backslash separators'   403 '/..\..\secret.txt'      --path-as-is
tdeny 'absolute /etc/passwd'   404 /etc/passwd
tdeny 'bad percent escape'     400 /%zz
tdeny 'truncated escape'       400 /%2
tdeny 'NUL via %00'            400 /ok.txt%00.jpg
tdeny 'bare %00'               400 /%00
tdeny 'encoded CR'             400 /ok%0d%0atxt
tdeny 'encoded DEL'            400 /ok%7f.txt

# A symlink inside the root whose target is outside it. The first two layers
# of the resolver cannot see this at all -- there is nothing hostile in the
# string "/escape" -- so this is the assertion that realpath(3) containment
# is doing the work.
tdeny 'symlink to a file outside' 403 /escape
tdeny 'symlink to a dir outside'  403 /escapedir/secret.txt
tdeny 'symlink dir, dir listing'  403 /escapedir/

# Never a dotfile, even though both of these are readable and inside root.
tstatus 'deny: dotfile'          403 /.hidden
tstatus 'deny: dot directory'    403 /.git/config
tstatus 'deny: encoded dotfile'  403 /%2ehidden

# Targets curl will not send.
traw 'relative target'        400 \
	"GET ../secret.txt HTTP/1.1\r\nHost: x\r\n\r\n"
traw 'asterisk-form target'   400 "GET * HTTP/1.1\r\nHost: x\r\n\r\n"
traw 'network-path target'    400 "GET //x/ok.txt HTTP/1.1\r\nHost: x\r\n\r\n"
tdeny 'network-path reference' 400 //ok.txt --path-as-is
traw 'absolute-form is ok'    200 \
	"GET http://x/ok.txt HTTP/1.1\r\nHost: x\r\n\r\n"
traw 'absolute-form traversal' 403 \
	"GET http://x/../secret.txt HTTP/1.1\r\nHost: x\r\n\r\n"
traw 'literal NUL in target'  400 \
	"GET /ok.txt\000x HTTP/1.1\r\nHost: x\r\n\r\n"
traw 'literal NUL in a field' 400 \
	"GET /ok.txt HTTP/1.1\r\nHost: x\r\nX-A: b\000c\r\n\r\n"

# And the belt-and-braces check: not one byte of the secret file has appeared
# in any response body this suite has collected.
if [ ! -s "$TD/allbodies" ]; then
	bad 'deny: secret never served' 'no response bodies were collected'
elif grep -q "$SECRET" "$TD/allbodies"; then
	bad 'deny: secret never served' \
	    'the SECRET appeared in a response body collected by this suite'
else
	ok 'deny: secret never served'
fi

# ---------------------------------------------------------------------------
# 6. byte-for-byte integrity
#
# cmp(1) is the oracle, not a checksum written here. A 10MB body does not fit
# in the 64KB output buffer, so this is also the only assertion that proves
# the partial-write pump works: it takes at least 160 refills, and any
# off-by-one in the offset arithmetic shows up as a byte that differs.
# ---------------------------------------------------------------------------
dl() { curl --http1.1 -sS --max-time 60 -o "$TD/dl" -D "$TD/h" "$@"; }

if dl "$U/big.bin" && cmp -s "$BIG" "$TD/dl"; then
	ok 'big: 10MB served byte for byte'
else
	bad 'big: 10MB served byte for byte' "$(cmp "$BIG" "$TD/dl" 2>&1)"
fi
if grep -q "^Content-Length: $BIGSZ" "$TD/h"; then
	ok 'big: Content-Length is the file size'
else
	bad 'big: Content-Length is the file size' "$(cat "$TD/h")"
fi
# ... and the bytes curl received are exactly Content-Length of them.
_n=$(wc -c <"$TD/dl")
if [ "$_n" = "$BIGSZ" ]; then ok 'big: body length matches'
else bad 'big: body length matches' "want $BIGSZ bytes, got $_n"; fi

# ---------------------------------------------------------------------------
# 7. Content-Type, by extension
#
# Two oracles. curl parses the header and reports it back through
# -w %{content_type}, so the comparison is against curl's parse and not
# against a grep of our own output. And file(1) answers the same question
# from the CONTENT of the same file -- a different program, a different
# method, no shared code -- for the four fixtures whose bytes really are
# what their extension claims.
# ---------------------------------------------------------------------------
# tctype NAME PATH WANT
tctype() {
	_g=$(curl --http1.1 -sS --max-time "$MT" -o /dev/null \
	          -w '%{content_type}' "$U$2" 2>&1)
	if [ "$_g" = "$3" ]; then ok "ctype: $1"
	else bad "ctype: $1" "want [$3], got [$_g]"; fi
}

tctype '.html'        /a.html        text/html
tctype '.HTML (case)' /a.HTML        text/html
tctype '.txt'         /ok.txt        text/plain
tctype '.css'         /a.css         text/css
tctype '.js'          /a.js          text/javascript
tctype '.json'        /a.json        application/json
tctype '.png'         /a.png         image/png
tctype '.gif'         /a.gif         image/gif
tctype '.svg'         /a.svg         image/svg+xml
tctype '.pdf'         /a.pdf         application/pdf
tctype 'unknown ext'  /a.unknownext  application/octet-stream
tctype 'no extension' /noextension   application/octet-stream
tctype 'dir -> index'  /sub/         text/html
tctype '.bin'         /big.bin       application/octet-stream

# file(1) reads the bytes; httpd reads the name. They must agree.
if command -v file >/dev/null 2>&1; then
	for f in a.html a.png a.gif a.pdf; do
		_fm=$(file --mime-type -b "$R/$f")
		_hm=$(curl --http1.1 -sS --max-time "$MT" -o /dev/null \
		           -w '%{content_type}' "$U/$f" 2>&1)
		if [ "$_fm" = "$_hm" ]; then ok "ctype: file(1) agrees on $f"
		else bad "ctype: file(1) agrees on $f" \
		         "file(1) says [$_fm], httpd says [$_hm]"; fi
	done
else
	for f in a.html a.png a.gif a.pdf; do
		skipt "ctype: file(1) agrees on $f" "no file(1)"
	done
fi

# ---------------------------------------------------------------------------
# 8. HEAD
#
# RFC 9110 9.3.2: identical to the GET response, minus the body. The
# assertion that matters is not "the body is empty" but "the headers are the
# same ones", which is checked by diffing the two header blocks with Date
# removed -- Date legitimately differs by a second.
# ---------------------------------------------------------------------------
tstatus 'head: 200'              200 /ok.txt -I
tstatus 'head: 404 for missing'  404 /nope   -I
tstatus 'head: 403 for dotfile'  403 /.hidden -I

fetch /ok.txt -I
cp "$TD/h" "$TD/head-h"

# curl -I writes the header block to -o as well, so "the body is empty"
# cannot be asserted by measuring curl's output file -- it was 121 bytes of
# headers and the assertion was measuring the wrong thing. Count the bytes
# after the terminator on the wire instead.
raw "HEAD /ok.txt HTTP/1.1\r\nHost: x\r\n\r\n"
_n=$(python3 -c 'import sys
d = open(sys.argv[1], "rb").read()
i = d.find(b"\r\n\r\n")
print(len(d) - i - 4 if i >= 0 else -1)' "$TD/raw")
if [ "$_n" = 0 ]; then ok 'head: not one body byte on the wire'
else bad 'head: not one body byte on the wire' "got $_n bytes after the headers"; fi
if grep -q '^Content-Length: 14' "$TD/raw"; then
	ok 'head: Content-Length still sent'
else
	bad 'head: Content-Length still sent' "$(head -c 200 "$TD/raw")"
fi

fetch /ok.txt
cp "$TD/h" "$TD/get-h"
grep -vi '^Date:' "$TD/head-h" >"$TD/head-h2"
grep -vi '^Date:' "$TD/get-h"  >"$TD/get-h2"
if diff -u "$TD/head-h2" "$TD/get-h2" >"$TD/hdiff" 2>&1; then
	ok 'head: headers identical to GET'
else
	bad 'head: headers identical to GET' "$(cat "$TD/hdiff")"
fi

# The big one too: Content-Length must be the file size, not zero.
fetch /big.bin -I
if grep -q "^Content-Length: $BIGSZ" "$TD/h"; then
	ok 'head: Content-Length is the real size'
else
	bad 'head: Content-Length is the real size' "$(cat "$TD/h")"
fi

# ---------------------------------------------------------------------------
# 9. conditional GET: Last-Modified and If-Modified-Since
#
# date(1) is the oracle for the Last-Modified value: it formats the same
# mtime from the same stat(2) through a completely different program, so
# agreement is a statement about the format and the timezone and not about
# our own strftime call being self-consistent. curl's -z is the oracle for
# the conditional itself, since curl builds the request date from the file
# on disk.
# ---------------------------------------------------------------------------
fetch /ok.txt
LM=$(sed -n 's/^Last-Modified: //p' "$TD/h" | tr -d '\r')
WANT_LM=$(date -u -d "@$(stat -c %Y "$R/ok.txt")" +'%a, %d %b %Y %H:%M:%S GMT')
if [ "$LM" = "$WANT_LM" ]; then ok 'cond: Last-Modified agrees with date(1)'
else bad 'cond: Last-Modified agrees with date(1)' \
         "httpd says [$LM], date(1) says [$WANT_LM]"; fi

tstatus 'cond: exact IMS is 304'   304 /ok.txt -H "If-Modified-Since: $LM"
tstatus 'cond: future IMS is 304'  304 /ok.txt \
        -H 'If-Modified-Since: Fri, 31 Dec 2038 23:59:59 GMT'
tstatus 'cond: old IMS is 200'     200 /ok.txt \
        -H 'If-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT'
# curl -z builds the date itself from the file's mtime.
tstatus 'cond: curl -z on the file' 304 /ok.txt -z "$R/ok.txt"
tstatus 'cond: curl -z 1990'        200 /ok.txt -z '1990-01-01'
tstatus 'cond: HEAD gets 304 too'   304 /ok.txt -I -H "If-Modified-Since: $LM"

# RFC 9110 13.1.3: an invalid HTTP-date in If-Modified-Since MUST be
# ignored. 400 would be the natural reflex for this program and it is wrong.
tstatus 'cond: junk IMS ignored'    200 /ok.txt \
        -H 'If-Modified-Since: not a date at all'
# Not with curl: `-H 'Name;'` tells curl to REMOVE the header, so the
# request went out with no If-Modified-Since at all and the assertion was
# vacuous. Raw, with a genuinely empty value.
traw 'empty IMS ignored'        200 \
	"GET /ok.txt HTTP/1.1\r\nHost: x\r\nIf-Modified-Since:\r\n\r\n"
tstatus 'cond: truncated IMS'       200 /ok.txt \
        -H 'If-Modified-Since: Sun, 06 Nov 1994'

# The two obsolete formats RFC 9110 5.6.7 still requires a recipient to
# accept. curl will not send either, so these are raw.
traw 'IMS in RFC 850 format'    304 \
	"GET /ok.txt HTTP/1.1\r\nHost: x\r\nIf-Modified-Since: Thursday, 31-Dec-37 23:59:59 GMT\r\n\r\n"
traw 'IMS in asctime format'    304 \
	"GET /ok.txt HTTP/1.1\r\nHost: x\r\nIf-Modified-Since: Fri Dec 31 23:59:59 2038\r\n\r\n"

# A 304 carries no body and claims no length. Both have to be true: a 304
# with a Content-Length desynchronises a keep-alive connection.
raw "GET /ok.txt HTTP/1.1\r\nHost: x\r\nIf-Modified-Since: $LM\r\n\r\n"
_n=$(python3 -c 'import sys
d = open(sys.argv[1], "rb").read()
i = d.find(b"\r\n\r\n")
print(len(d) - i - 4 if i >= 0 else -1)' "$TD/raw")
if [ "$_n" = 0 ]; then ok 'cond: 304 has no body'
else bad 'cond: 304 has no body' "got $_n bytes after the headers"; fi
# A negative grep over a file that may be empty is the textbook vacuous
# assertion: replacing t/raw.py with `sys.exit(0)` left this one green among
# 71 loud failures. The response has to exist before its headers can be
# checked for an absence.
if ! grep -qi '^HTTP/1\.[01] 304' "$TD/raw"; then
	bad 'cond: 304 has no Content-Length' \
	    "no 304 status line in the response at all" "$(head -c 200 "$TD/raw")"
elif grep -qi '^Content-Length:' "$TD/raw"; then
	bad 'cond: 304 has no Content-Length' "$(head -c 200 "$TD/raw")"
else
	ok 'cond: 304 has no Content-Length'
fi
if grep -q "^Last-Modified: $LM" "$TD/raw"; then
	ok 'cond: 304 repeats Last-Modified'
else
	bad 'cond: 304 repeats Last-Modified' "$(head -c 200 "$TD/raw")"
fi

# ---------------------------------------------------------------------------
# 9b. entity tags: ETag and If-None-Match
#
# The reason this header exists here is the last block of assertions in this
# section. An HTTP-date carries one second, so a file rewritten twice inside
# one second is served stale to every client that revalidates by date, and
# there is nothing If-Modified-Since can do about it. st_mtim.tv_nsec can.
#
# curl is the oracle for the protocol dance itself: --etag-save parses the
# ETag out of the response with curl's own parser and --etag-compare builds
# the If-None-Match request from it, so neither the reading of the header nor
# the writing of the request is ours. The comparison rules come from RFC
# 9110: 13.1.2 for the weak comparison, the "*" form and the list form, and
# 13.1.3 for "a recipient MUST ignore If-Modified-Since if the request
# contains an If-None-Match header field".
#
# No second HTTP server is installed on this machine, so there is no other
# implementation to diff these answers against. The README says so rather
# than pretending otherwise.
# ---------------------------------------------------------------------------
fetch /ok.txt
ET=$(sed -n 's/^ETag: //p' "$TD/h" | tr -d '\r')
case "$ET" in
'"'*'"') ok 'etag: 200 carries a quoted strong ETag' ;;
*)       bad 'etag: 200 carries a quoted strong ETag' "ETag is [$ET]" ;;
esac

# A constant ETag satisfies almost every assertion below, so one of them has
# to be that two different files do not share a tag.
fetch /sub/deep.txt
ET_DEEP=$(sed -n 's/^ETag: //p' "$TD/h" | tr -d '\r')
if [ -n "$ET" ] && [ "$ET" != "$ET_DEEP" ]; then
	ok 'etag: two files have two tags'
else
	bad 'etag: two files have two tags' "both are [$ET]"
fi

# curl does the whole dance: it parses the tag out of the 200 and builds the
# conditional request itself.
rm -f "$TD/et"
curl --http1.1 -sS --max-time "$MT" --etag-save "$TD/et" -o /dev/null \
     "$U/ok.txt" 2>"$TD/curlerr"
SAVED=$(tr -d '\r\n' < "$TD/et" 2>/dev/null)
if [ -z "$SAVED" ]; then
	skipt 'etag: curl --etag-save read the tag' \
	      "this curl saved nothing: $(cat "$TD/curlerr")"
	skipt 'etag: curl --etag-compare gets 304' 'no saved tag to compare'
elif [ "$SAVED" = "$ET" ]; then
	ok 'etag: curl --etag-save read the tag'
	tstatus 'etag: curl --etag-compare gets 304' 304 /ok.txt \
	        --etag-compare "$TD/et"
else
	bad 'etag: curl --etag-save read the tag' \
	    "curl saved [$SAVED], the header said [$ET]"
	tstatus 'etag: curl --etag-compare gets 304' 304 /ok.txt \
	        --etag-compare "$TD/et"
fi

# Both directions, because a comparison that never matches tests only the
# miss path and a comparison that always matches tests only the hit path.
tstatus 'etag: the matching tag is 304'  304 /ok.txt -H "If-None-Match: $ET"
tstatus 'etag: a wrong tag is 200'       200 /ok.txt \
        -H 'If-None-Match: "not-this-one"'
tbody   'etag: a wrong tag sends the body' 'plain text ok' /ok.txt \
        -H 'If-None-Match: "not-this-one"'
tstatus 'etag: HEAD gets 304 too'        304 /ok.txt -I -H "If-None-Match: $ET"

# RFC 9110 13.1.2: "*" matches whenever a current representation exists.
tstatus 'etag: If-None-Match * is 304'   304 /ok.txt -H 'If-None-Match: *'
tstatus 'etag: * on a dir index is 304'  304 /     -H 'If-None-Match: *'
# ...and when none exists the condition is false, so the request proceeds
# and gets the answer it would have got anyway. Not 304.
tstatus 'etag: * on a missing file is 404' 404 /nope.txt -H 'If-None-Match: *'

# The weak comparison function, which 13.1.2 requires for If-None-Match and
# not for If-Match or If-Range: W/"x" and "x" are the same tag here.
tstatus 'etag: the weak form of the tag is 304' 304 /ok.txt \
        -H "If-None-Match: W/$ET"
tstatus 'etag: a list containing the tag is 304' 304 /ok.txt \
        -H "If-None-Match: \"a\", W/\"b\", $ET"
tstatus 'etag: a list without it is 200'         200 /ok.txt \
        -H 'If-None-Match: "a", W/"b", "c"'
# Nothing in 13.1.2 makes a malformed If-None-Match an error, and refusing
# one would be this program's usual reflex and wrong here, the same way it
# is wrong for If-Modified-Since.
tstatus 'etag: an unparseable tag list is 200' 200 /ok.txt \
        -H 'If-None-Match: not a tag at all'
traw 'empty If-None-Match ignored' 200 \
	"GET /ok.txt HTTP/1.1\r\nHost: x\r\nIf-None-Match:\r\n\r\n"

# RFC 9110 13.1.3: If-None-Match present means If-Modified-Since is IGNORED,
# not combined. These two assertions are the ones that separate that from
# "evaluate both and take either", and the first is the one that matters:
# the wrong version answers 304 to a client whose cached copy is stale.
tstatus 'etag: a stale tag beats a satisfied date' 200 /ok.txt \
        -H 'If-None-Match: "stale"' -H "If-Modified-Since: $LM"
tstatus 'etag: a matching tag beats an old date'   304 /ok.txt \
        -H "If-None-Match: $ET" \
        -H 'If-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT'

# RFC 9110 13.2.2 evaluates the precondition before Range.
tstatus 'etag: 304 beats 206' 304 /ok.txt -H "If-None-Match: $ET" \
        -H 'Range: bytes=0-1'
# ...and a 206 that is actually sent carries the same validator as the 200,
# because it is the same representation.
fetch /ok.txt -H 'Range: bytes=0-3'
ET_206=$(sed -n 's/^ETag: //p' "$TD/h" | tr -d '\r')
if [ -n "$ET" ] && [ "$ET_206" = "$ET" ]; then
	ok 'etag: the 206 carries the same tag'
else
	bad 'etag: the 206 carries the same tag' "206 says [$ET_206], 200 said [$ET]"
fi

# A 304 carries no body and repeats the validator. Both halves: a 304 with a
# body is a protocol violation real clients mishandle, and a 304 with no
# ETag leaves a client that revalidated by tag nothing it can store
# (RFC 9110 15.4.5). The status line is checked first, because a negative
# grep over a response that never arrived passes for the wrong reason.
raw "GET /ok.txt HTTP/1.1\r\nHost: x\r\nIf-None-Match: $ET\r\n\r\n"
_n=$(python3 -c 'import sys
d = open(sys.argv[1], "rb").read()
i = d.find(b"\r\n\r\n")
print(len(d) - i - 4 if i >= 0 else -1)' "$TD/raw")
if ! grep -qi '^HTTP/1\.[01] 304' "$TD/raw"; then
	bad 'etag: the 304 has no body' "no 304 status line at all" \
	    "$(head -c 200 "$TD/raw")"
	bad 'etag: the 304 repeats the ETag' "no 304 status line at all"
	bad 'etag: the 304 has no Content-Length' "no 304 status line at all"
else
	if [ "$_n" = 0 ]; then ok 'etag: the 304 has no body'
	else bad 'etag: the 304 has no body' "got $_n bytes after the headers"; fi
	if grep -qF "ETag: $ET" "$TD/raw"; then
		ok 'etag: the 304 repeats the ETag'
	else
		bad 'etag: the 304 repeats the ETag' "want [$ET]" \
		    "$(head -c 300 "$TD/raw")"
	fi
	if grep -qi '^Content-Length:' "$TD/raw"; then
		bad 'etag: the 304 has no Content-Length' "$(head -c 300 "$TD/raw")"
	else
		ok 'etag: the 304 has no Content-Length'
	fi
fi

# ---------------------------------------------------------------------------
# the hole If-Modified-Since cannot see
#
# Two generations of one file: same size, same mtime SECOND, different
# nanoseconds. That is what an editor saving twice or a build system
# rewriting an asset produces routinely. The timestamps are set by python so
# the assertion does not depend on winning a race against the wall clock,
# which is the kind of test that passes on a fast machine and fails in CI.
# ---------------------------------------------------------------------------
python3 - "$R/twice.txt" <<'PYTWICE'
import os, sys
open(sys.argv[1], "w").write("AAAA\n")
os.utime(sys.argv[1], ns=(1700000000111111111, 1700000000111111111))
PYTWICE
fetch /twice.txt
T_LM=$(sed -n 's/^Last-Modified: //p' "$TD/h" | tr -d '\r')
T_ET=$(sed -n 's/^ETag: //p' "$TD/h" | tr -d '\r')
python3 - "$R/twice.txt" <<'PYTWICE'
import os, sys
open(sys.argv[1], "w").write("BBBB\n")
os.utime(sys.argv[1], ns=(1700000000222222222, 1700000000222222222))
PYTWICE

# This one passes BECAUSE If-Modified-Since cannot do better, and it is here
# so that the line after it means something. The bytes on disk have changed
# and the date-based conditional says they have not.
tstatus 'etag: by date, a same-second rewrite looks unchanged' 304 \
        /twice.txt -H "If-Modified-Since: $T_LM"
tstatus 'etag: by tag, the same rewrite is a 200' 200 \
        /twice.txt -H "If-None-Match: $T_ET"
tbody   'etag: and the new bytes are what arrive' 'BBBB' \
        /twice.txt -H "If-None-Match: $T_ET"
fetch /twice.txt
T_ET2=$(sed -n 's/^ETag: //p' "$TD/h" | tr -d '\r')
T_LM2=$(sed -n 's/^Last-Modified: //p' "$TD/h" | tr -d '\r')
if [ -n "$T_ET" ] && [ "$T_ET" != "$T_ET2" ]; then
	ok 'etag: the tag changed with the nanoseconds'
else
	bad 'etag: the tag changed with the nanoseconds' "both are [$T_ET]"
fi
# ...while Last-Modified did not move at all, which is the whole point.
if [ -n "$T_LM" ] && [ "$T_LM" = "$T_LM2" ]; then
	ok 'etag: Last-Modified did not move'
else
	bad 'etag: Last-Modified did not move' "was [$T_LM], now [$T_LM2]"
fi

# ---------------------------------------------------------------------------
# 10. byte ranges
#
# The oracle is the file on disk cut with tail(1) and head(1) -- two
# coreutils programs doing the arithmetic independently -- and cmp(1)
# comparing their answer with the bytes curl received. Boundaries are chosen
# around the 64KB output buffer, because that is where an off-by-one in the
# pump hides, and at both ends of the file.
# ---------------------------------------------------------------------------
# trange NAME PATH SPEC START LEN SIZE
trange() {
	_n=$1; _p=$2; _spec=$3; _s=$4; _l=$5; _sz=$6
	ST=$(curl --http1.1 -sS --max-time "$MT" -o "$TD/dl" -D "$TD/h" \
	          -w '%{http_code}' -H "Range: bytes=$_spec" "$U$_p" 2>&1) \
	    || ST="curl-exit-$?"
	if [ "$ST" != 206 ]; then
		bad "range: $_n" "want 206, got $ST"; return
	fi
	tail -c +$((_s + 1)) "$R${_p}" | head -c "$_l" > "$TD/want"
	_cr="bytes $_s-$((_s + _l - 1))/$_sz"
	# Strip the CRs first: a header line ends with CRLF, so "$" never
	# anchors against it and an unanchored grep would match a prefix of a
	# longer size. This cost 24 red assertions against correct headers.
	tr -d '\r' <"$TD/h" >"$TD/h2"
	if ! grep -q "^Content-Range: $_cr\$" "$TD/h2"; then
		bad "range: $_n" "want [Content-Range: $_cr]" "$(cat "$TD/h")"
		return
	fi
	if cmp -s "$TD/want" "$TD/dl"; then ok "range: $_n"
	else bad "range: $_n" "$(cmp "$TD/want" "$TD/dl" 2>&1)"; fi
}

# t416 NAME PATH SPEC SIZE
t416() {
	fetch "$2" -H "Range: bytes=$3"
	tr -d '\r' <"$TD/h" >"$TD/h2"
	if [ "$ST" != 416 ]; then
		bad "range: $1" "want 416, got $ST"
	elif grep -q "^Content-Range: bytes \*/$4\$" "$TD/h2"; then
		ok "range: $1"
	else
		bad "range: $1" "want [Content-Range: bytes */$4]" "$(cat "$TD/h")"
	fi
}

thdr 'range: Accept-Ranges advertised' '^Accept-Ranges: bytes' /ok.txt

B=$BIGSZ
trange 'first byte'        /big.bin '0-0'                0          1       "$B"
trange 'first two'         /big.bin '0-1'                0          2       "$B"
trange 'byte 1 only'       /big.bin '1-1'                1          1       "$B"
trange 'exactly one buffer' /big.bin '0-65535'           0          65536   "$B"
trange 'one buffer plus 1' /big.bin '0-65536'            0          65537   "$B"
trange 'across the seam'   /big.bin '65535-65536'        65535      2       "$B"
trange 'second buffer'     /big.bin '65536-131071'       65536      65536   "$B"
trange 'last two bytes'    /big.bin "$((B - 2))-$((B - 1))" $((B - 2)) 2     "$B"
trange 'last byte'         /big.bin "$((B - 1))-$((B - 1))" $((B - 1)) 1     "$B"
trange 'open-ended'        /big.bin "$((B - 100))-"      $((B - 100)) 100    "$B"
trange 'whole file by range' /big.bin "0-$((B - 1))"     0          "$B"     "$B"
trange 'suffix 1'          /big.bin '-1'                 $((B - 1)) 1       "$B"
trange 'suffix 65537'      /big.bin '-65537'             $((B - 65537)) 65537 "$B"
# last-byte-pos past the end is clamped, NOT refused (RFC 9110 14.1.2).
trange 'last-pos clamped'  /big.bin "0-$((B + 1000))"    0          "$B"     "$B"
trange 'suffix past start' /big.bin "-$((B + 1000))"     0          "$B"     "$B"
trange 'small file whole'  /ok.txt  '0-13'               0          14      14
trange 'small file clamped' /ok.txt '0-99'               0          14      14
trange 'small file last'   /ok.txt  '13-13'              13         1       14

# Unsatisfiable: first-byte-pos at or past the end, and a zero-length suffix.
t416 'first-pos == size'   /ok.txt  '14-14'   14
t416 'first-pos past size' /ok.txt  '9999-'   14
t416 'zero-length suffix'  /ok.txt  '-0'      14
t416 'range on empty file' /empty.txt '0-0'   0

# A multi-range request. This server refuses it rather than building a
# multipart/byteranges body; RFC 9110 14.2 would also allow ignoring the
# header and sending 200, so this is a deviation and it is deliberate.
t416 'multi-range refused'  /ok.txt '0-1,5-6'  14
t416 'multi-range on big'   /big.bin '0-1,5-6' "$B"

# Malformed or unknown-unit Range: IGNORED, whole body, 200. Not 416 --
# these are the cases RFC 9110 14.2 says to ignore, and confusing them with
# the unsatisfiable cases above is the easy mistake.
tstatus 'range: unknown unit ignored'  200 /ok.txt -H 'Range: items=0-1'
tstatus 'range: no equals ignored'     200 /ok.txt -H 'Range: bytes 0-1'
tstatus 'range: non-numeric ignored'   200 /ok.txt -H 'Range: bytes=a-b'
tstatus 'range: reversed ignored'      200 /ok.txt -H 'Range: bytes=9-1'
tstatus 'range: empty spec ignored'    200 /ok.txt -H 'Range: bytes='
tbody   'range: ignored means full'   'plain text ok' /ok.txt -H 'Range: bytes=a-b'

# Conditional wins over Range: RFC 9110 13.2.2 evaluates If-Modified-Since
# before Range, so this is a 304 and not a 206.
tstatus 'range: 304 beats 206' 304 /ok.txt -H "If-Modified-Since: $LM" \
        -H 'Range: bytes=0-1'

# HEAD with a Range: the 206 headers, and no body.
raw "HEAD /ok.txt HTTP/1.1\r\nHost: x\r\nRange: bytes=0-3\r\n\r\n"
if grep -q '^Content-Range: bytes 0-3/14' "$TD/raw" &&
   grep -q '^Content-Length: 4' "$TD/raw"; then
	ok 'range: HEAD gets 206 headers'
else
	bad 'range: HEAD gets 206 headers' "$(head -c 300 "$TD/raw")"
fi

# ---------------------------------------------------------------------------
# 11. request bodies: Content-Length and chunked
#
# GET has no use for a body, but a body that is not read is not gone: it
# stays in the socket and becomes the next request on a keep-alive
# connection. curl is the oracle for well-formed chunked framing -- given
# Transfer-Encoding: chunked it does the chunking itself -- and raw.py for
# the malformed cases.
# ---------------------------------------------------------------------------
tstatus 'body: CL body on GET'     200 /ok.txt -X GET -d 'hello world'
tstatus 'body: empty CL body'      200 /ok.txt -X GET -d ''
tstatus 'body: curl chunks it'     200 /ok.txt -X GET \
        -H 'Transfer-Encoding: chunked' -d 'hello world'
# 2MB through curl's chunker: more than one read, and over MAXBODY.
head -c 2097152 "$BIG" > "$TD/2mb"
tstatus 'body: 2MB chunked is 413'  413 /ok.txt -X GET \
        -H 'Transfer-Encoding: chunked' --data-binary "@$TD/2mb"
tstatus 'body: 2MB CL is 413'       413 /ok.txt -X GET \
        --data-binary "@$TD/2mb"
# Both of those are also the assertion for the lingering close. The server
# answers 413 while curl is still sending, and close(2) on a socket with
# unread data in its receive queue makes the kernel send RST -- which
# discards the response that was already on its way. Without the
# shutdown-and-drain, curl reports "(55) Send failure: Connection reset by
# peer" here and never sees the 413.
# Just under the cap must still be served, or the 413 above proves nothing.
head -c 1000000 "$BIG" > "$TD/1mb"
tstatus 'body: 1MB chunked is 200'  200 /ok.txt -X GET \
        -H 'Transfer-Encoding: chunked' --data-binary "@$TD/1mb"

traw 'chunked, one chunk'       200 \
	"GET /ok.txt HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
traw 'chunked, several chunks'  200 \
	"GET /ok.txt HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n2\r\nbc\r\n3\r\ndef\r\n0\r\n\r\n"
traw 'chunked, upper-case hex'  200 \
	"GET /ok.txt HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nA\r\n0123456789\r\n0\r\n\r\n"
traw 'chunked, chunk-ext'       200 \
	"GET /ok.txt HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5;name=value\r\nhello\r\n0\r\n\r\n"
traw 'chunked, with trailer'    200 \
	"GET /ok.txt HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Trailer: v\r\n\r\n"
traw 'chunked, empty body'      200 \
	"GET /ok.txt HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"

traw 'chunk size not hex'       400 \
	"GET /ok.txt HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nhello\r\n0\r\n\r\n"
traw 'chunk size empty'         400 \
	"GET /ok.txt HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n\r\nhello\r\n0\r\n\r\n"
traw 'chunk size negative'      400 \
	"GET /ok.txt HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n-5\r\nhello\r\n0\r\n\r\n"
# 17 hex digits: overflows a 64-bit size. The check is on the accumulator,
# before the multiply, so it cannot wrap.
traw 'chunk size overflows'     400 \
	"GET /ok.txt HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffffff\r\nx\r\n0\r\n\r\n"
traw 'chunk size huge but sane' 413 \
	"GET /ok.txt HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n7fffffff\r\nx\r\n"
traw 'no CRLF after chunk data' 400 \
	"GET /ok.txt HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX0\r\n\r\n"
traw 'chunk-size line too long' 400 \
	"GET /ok.txt HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n000000000000000000000000000000000000000000000000000000000000000000000000000000000005\r\nhello\r\n0\r\n\r\n"

# An unterminated chunked body: no final zero chunk, and the peer closes.
# The server must not answer, and must not die. raw.py exits 3 when nothing
# came back.
printf '%b' "GET /ok.txt HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n" \
	| python3 "$ROOT/t/raw.py" "$PORT" >"$TD/raw" 2>&1
_rc=$?
if [ "$_rc" = 3 ] && [ ! -s "$TD/raw" ]; then
	ok 'raw: unterminated chunked gets no response'
else
	bad 'raw: unterminated chunked gets no response' \
	    "raw.py exit $_rc, output: $(head -c 200 "$TD/raw")"
fi

# ---------------------------------------------------------------------------
# 12. keep-alive
#
# curl is the oracle, and a good one here: %{num_connects} is curl's own
# count of TCP connections it had to open. Give curl several URLs on one
# command line and it reuses the connection if the server lets it -- so the
# expected output is "1" for the first transfer and "0" for every one after.
# Nothing about this is visible in a status code.
# ---------------------------------------------------------------------------
# tconn NAME WANT-DIGITS [curl args...]
#
# Every URL needs its own -o: curl maps -o options to URLs positionally, so a
# single "-o /dev/null" sends the first body to the bin and every later body
# to stdout -- where it lands in the middle of the %{num_connects} digits
# this assertion reads. That is how it failed the first time.
tconn() {
	_n=$1; _w=$2; shift 2
	_g=$(curl --http1.1 -sS --max-time "$MT" \
	         -w '%{num_connects}' "$@" 2>&1)
	if [ "$_g" = "$_w" ]; then ok "keep: $_n"
	else bad "keep: $_n" "want num_connects [$_w], got [$_g]"; fi
}
N=/dev/null

tconn 'two requests, one connection'  10 -o $N "$U/ok.txt" -o $N "$U/a.css"
tconn 'five requests, one connection' 10000 \
	-o $N "$U/ok.txt" -o $N "$U/a.css" -o $N "$U/a.js" \
	-o $N "$U/sub/deep.txt" -o $N "$U/index.html"
tconn 'HEAD then GET reuse'           10 -I -o $N "$U/ok.txt" -o $N "$U/a.css"
tconn 'a 206 does not close'          10 -H 'Range: bytes=0-3' \
	-o $N "$U/ok.txt" -o $N "$U/a.css"
tconn '304 does not close'            10 -H "If-Modified-Since: $LM" \
	-o $N "$U/ok.txt" -o $N "$U/ok.txt"
# A body on the first request must be drained, or the second request is read
# out of the first one's body.
tconn 'after a CL body'               10 -X GET -d 'hello' \
	-o $N "$U/ok.txt" -o $N "$U/a.css"
tconn 'after a chunked body'          10 -X GET \
	-H 'Transfer-Encoding: chunked' -d 'hello' \
	-o $N "$U/ok.txt" -o $N "$U/a.css"
# ... and the controls: Connection: close really does close, so curl has to
# open a second connection.
tconn 'Connection: close closes'      11 -H 'Connection: close' \
	-o $N "$U/ok.txt" -o $N "$U/a.css"
tconn 'HTTP/1.0 closes by default'    11 --http1.0 \
	-o $N "$U/ok.txt" -o $N "$U/a.css"
tconn 'HTTP/1.0 + keep-alive reuses'  10 --http1.0 \
	-H 'Connection: keep-alive' -o $N "$U/ok.txt" -o $N "$U/a.css"
# A refusal closes, deliberately: it is answered before the body drainer has
# run, so the connection cannot be trusted to hold another request.
tconn '404 closes'                    11 -o $N "$U/nope" -o $N "$U/ok.txt"

thdr 'keep: Connection: keep-alive sent' '^Connection: keep-alive' /ok.txt
thdr 'keep: Connection: close honoured'  '^Connection: close' /ok.txt \
     -H 'Connection: close'

# Pipelining: two requests in one write, two responses, in order. This is
# the assertion that the body drainer leaves the stream aligned -- the
# chunked body of the first request must not be read as the second request.
rawcount() {   # rawcount NAME WANT-RESPONSES REQUEST
	raw "$3"
	_g=$(grep -c '^HTTP/1\.1 ' "$TD/raw")
	if [ "$_g" = "$2" ]; then ok "pipeline: $1"
	else bad "pipeline: $1" "want $2 responses, got $_g" \
	         "$(head -c 400 "$TD/raw")"; fi
}
rawcount 'two GETs in one write' 2 \
	"GET /ok.txt HTTP/1.1\r\nHost: x\r\n\r\nGET /sub/deep.txt HTTP/1.1\r\nHost: x\r\n\r\n"
rawcount 'three GETs in one write' 3 \
	"GET /ok.txt HTTP/1.1\r\nHost: x\r\n\r\nGET /ok.txt HTTP/1.1\r\nHost: x\r\n\r\nGET /ok.txt HTTP/1.1\r\nHost: x\r\n\r\n"
rawcount 'chunked body then a GET' 2 \
	"GET /ok.txt HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\nGET /sub/deep.txt HTTP/1.1\r\nHost: x\r\n\r\n"
rawcount 'CL body then a GET' 2 \
	"GET /ok.txt HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhelloGET /sub/deep.txt HTTP/1.1\r\nHost: x\r\n\r\n"
# The smuggling shape: if the body were NOT drained, "GET /secret" inside it
# would be answered as a second request. Exactly one response, and the
# second "request" stays a body.
rawcount 'body is not a request' 1 \
	"GET /ok.txt HTTP/1.1\r\nHost: x\r\nContent-Length: 39\r\n\r\nGET /sub/deep.txt HTTP/1.1\r\nHost: x\r\n\r\n"

# ---------------------------------------------------------------------------
# 13. concurrency, and clients that misbehave
#
# One process, one thread, poll(2). None of the properties in this section
# are visible in a single request's status code: the question is whether the
# server is still there afterwards.
# ---------------------------------------------------------------------------
# 100 simultaneous connections through curl --parallel. Each transfer gets
# its own -o line in the config file, and the assertion counts the 200s --
# "curl exited 0" would also be true if it had run them one at a time.
: >"$TD/par.cfg"
i=0
while [ "$i" -lt 100 ]; do
	printf 'url = "%s/big.bin"\noutput = "%s"\nrange = "0-4095"\n' \
	       "$U" "$TD/par.$i" >>"$TD/par.cfg"
	i=$((i + 1))
done
curl --http1.1 -sS --max-time 60 --parallel --parallel-max 100 \
     -K "$TD/par.cfg" -w '%{http_code}\n' >"$TD/par.out" 2>"$TD/par.err"
_n=$(grep -c '^206$' "$TD/par.out")
if [ "$_n" = 100 ]; then ok 'conc: 100 parallel transfers all 206'
else bad 'conc: 100 parallel transfers all 206' \
         "only $_n of 100 were 206" "$(head -3 "$TD/par.err")"; fi
# ... and every one of them got the right 4096 bytes.
head -c 4096 "$BIG" >"$TD/par.want"
_bad=0
i=0
while [ "$i" -lt 100 ]; do
	cmp -s "$TD/par.want" "$TD/par.$i" || _bad=$((_bad + 1))
	i=$((i + 1))
done
if [ "$_bad" = 0 ]; then ok 'conc: all 100 bodies byte-identical'
else bad 'conc: all 100 bodies byte-identical' "$_bad of 100 differed"; fi

# 100 connections held open at once, each doing two keep-alive requests, as
# background curls rather than one parallel curl -- a different shape of
# concurrency, and the one that fills the poll(2) array from 100 separate
# processes.
i=0
BGPIDS=
while [ "$i" -lt 100 ]; do
	curl --http1.1 -sS --max-time 30 -o /dev/null "$U/ok.txt" \
	     -o /dev/null "$U/a.css" -w '%{num_connects}' \
	     >"$TD/bg.$i" 2>&1 &
	BGPIDS="$BGPIDS $!"
	i=$((i + 1))
done
# NOT a bare `wait`: the server is a background job of this same shell, so
# `wait` with no arguments waits for httpd too and the suite hangs forever.
# That is exactly the failure mode the Makefile promises cannot happen, and
# it happened here first.
for _p in $BGPIDS; do wait "$_p"; done
# Per file, not `cat ... | grep -c`: curl's -w output has no trailing
# newline, so concatenating a hundred of them makes one 200-character line
# and the count is always 0.
_reuse=0
i=0
while [ "$i" -lt 100 ]; do
	[ "$(cat "$TD/bg.$i")" = 10 ] && _reuse=$((_reuse + 1))
	i=$((i + 1))
done
if [ "$_reuse" = 100 ]; then ok 'conc: 100 background curls, all reused'
else bad 'conc: 100 background curls, all reused' \
         "$_reuse of 100 reported num_connects 10" "$(cat "$TD/bg".0)"; fi

# A client that walks away in the middle of a 10MB response. raw.py --abort
# reads 100 bytes and then closes with SO_LINGER 0, so the kernel sends RST
# and the server's next write(2) fails. Five times, because the first one
# could be survived by luck.
# Each abort has to have actually read something, or this asserts only that
# raw.py exits 0 and the server is alive -- which `sys.exit(0)` in place of
# t/raw.py satisfies, no connection required. --abort 100 reads 100 bytes
# before resetting, so 100 bytes is what each round must report.
_ok=1
_got=0
i=0
while [ "$i" -lt 5 ]; do
	if printf '%b' "GET /big.bin HTTP/1.1\r\nHost: x\r\n\r\n" \
		| python3 "$ROOT/t/raw.py" "$PORT" --abort 100 >"$TD/abort.out" 2>&1
	then
		_n=$(wc -c < "$TD/abort.out")
		[ "$_n" -ge 100 ] && _got=$((_got + 1))
	else
		_ok=0
	fi
	i=$((i + 1))
done
if [ "$_ok" = 1 ] && [ "$_got" = 5 ] && kill -0 "$SRV" 2>/dev/null; then
	ok 'conc: survives 5 mid-response disconnects'
else
	bad 'conc: survives 5 mid-response disconnects' \
	    "$_got of 5 rounds read their 100 bytes" \
	    "server alive: $(kill -0 "$SRV" 2>/dev/null && echo yes || echo NO)"
fi
# And it still works afterwards, which "still running" alone does not prove.
tbody 'conc: serves correctly after RSTs' 'plain text ok' /ok.txt

# SIGPIPE. Writing to a peer that has gone must be an errno and not a
# signal, and the kernel is the authority on whether this process is
# ignoring it: bit 12 of SigIgn in /proc/PID/status is signal 13.
_mask=$(sed -n 's/^SigIgn:\s*//p' "/proc/$SRV/status" 2>/dev/null)
if [ -n "$_mask" ] && [ "$(python3 -c "print(int('$_mask', 16) >> 12 & 1)")" = 1 ]
then
	ok 'conc: SIGPIPE is ignored (per /proc/PID/status)'
else
	bad 'conc: SIGPIPE is ignored (per /proc/PID/status)' \
	    "SigIgn mask is [$_mask]"
fi

# ---------------------------------------------------------------------------
# 14. slow loris, and the reaping rule
#
# These need a server with a one-second deadline, so there is a second
# instance on its own ephemeral port. Both are killed from the trap.
#
# The rule being asserted: while a request is still arriving the deadline is
# on the REQUEST, not on inactivity. A plain idle timeout does not stop a
# loris, because one byte every N-1 seconds resets it forever.
# ---------------------------------------------------------------------------
"$HTTPD" -r "$R" -t 1 >"$TD/port2" 2>"$TD/log2" &
SRV2=$!
trap 'kill "$SRV" "$SRV2" 2>/dev/null; wait "$SRV" "$SRV2" 2>/dev/null' \
	EXIT INT TERM
PORT2=
i=0
while [ "$i" -lt 100 ]; do
	PORT2=$(sed -n 's/^listening [0-9.]*:\([0-9][0-9]*\)$/\1/p' "$TD/port2")
	[ -n "$PORT2" ] && break
	sleep 0.05
	i=$((i + 1))
done
if [ -z "$PORT2" ]; then
	bad 'loris: second server started' "$(cat "$TD/log2")"
else
	ok 'loris: second server started'

	# raw2 REQUEST [args...] -- against the -t 1 server
	raw2() {
		_q=$1; shift
		printf '%b' "$_q" \
			| python3 "$ROOT/t/raw.py" "$PORT2" "$@" \
			  >"$TD/raw2" 2>"$TD/raw2err"
		RST2=$(sed -n '1s|^HTTP/1\.[01] \([0-9][0-9]*\).*|\1|p' \
		       "$TD/raw2" | tr -d '\r')
	}
	REQ="GET /ok.txt HTTP/1.1\r\nHost: x\r\n\r\n"

	# Control first: the -t 1 server answers a normal request, and
	# answers one dripped fast enough to beat the deadline. Without
	# these two, "the loris was refused" is also true of a server that
	# refuses everything.
	raw2 "$REQ"
	if [ "$RST2" = 200 ]; then ok 'loris: fast request is 200'
	else bad 'loris: fast request is 200' "got [$RST2]"; fi

	raw2 "$REQ" --drip 5
	if [ "$RST2" = 200 ]; then ok 'loris: 5ms/byte drip is 200'
	else bad 'loris: 5ms/byte drip is 200' "got [$RST2]"; fi

	# The loris: 38 bytes at 100ms apiece is 3.8 seconds, which is past
	# the one-second deadline even though the connection is never idle
	# for more than 100ms. 408, or a close with no response -- both are
	# refusals, and the assertion is that it is not a 200.
	#
	# 100ms and not 60ms: the deadline is checked against time(2) in
	# whole seconds, so with -t 1 it can fire anywhere between 1.0 and
	# 2.0 seconds after the first byte. At 60ms the request finished at
	# 2.16s, which left 160ms of margin and failed intermittently under
	# load. The deadline is the thing under test, not the clock's
	# resolution.
	# 408 is the refusal. An empty $RST2 -- no response at all -- used to
	# be accepted here too, which means a raw client that did nothing
	# passed: t/raw.py replaced by `sys.exit(0)` left this green. httpd
	# does answer 408, so that is what is required; a closed connection
	# with no status line is a different behaviour and wants saying.
	raw2 "$REQ" --drip 100
	if [ "$RST2" = 408 ]; then
		ok 'loris: 100ms/byte drip is refused'
	elif [ -z "$RST2" ]; then
		bad 'loris: 100ms/byte drip is refused' \
		    "no response at all -- the connection closed without a status line"
	else
		bad 'loris: 100ms/byte drip is refused' \
		    "got [$RST2], which means the deadline was reset by each byte"
	fi

	# An idle keep-alive connection is reaped. The -t 1 server must drop
	# it within 3 seconds; the -t 5 server must still be holding it
	# after 1 second -- the control that stops "CLOSED" from being the
	# answer to every question.
	raw2 "$REQ" --linger 3
	if grep -q CLOSED "$TD/raw2"; then
		ok 'loris: idle keep-alive reaped at -t 1'
	else
		bad 'loris: idle keep-alive reaped at -t 1' \
		    "$(tail -1 "$TD/raw2")"
	fi
	raw "$REQ" --linger 1
	if grep -q OPEN "$TD/raw"; then
		ok 'loris: idle keep-alive held at -t 5'
	else
		bad 'loris: idle keep-alive held at -t 5' \
		    "$(tail -1 "$TD/raw")"
	fi

	# A connection that says nothing at all is reaped too, and silently:
	# there is no request to answer with 408. raw.py exits 3 when the
	# server closed without sending a byte.
	printf '' | python3 "$ROOT/t/raw.py" "$PORT2" --keep --timeout 4 \
		>"$TD/raw2" 2>&1
	_rc=$?
	if [ "$_rc" = 3 ]; then ok 'loris: silent connection reaped'
	else bad 'loris: silent connection reaped' \
	         "raw.py exit $_rc, output [$(cat "$TD/raw2")]"; fi

	# And the slow server is still serving afterwards.
	raw2 "$REQ"
	if [ "$RST2" = 200 ]; then ok 'loris: still serving after all that'
	else bad 'loris: still serving after all that' "got [$RST2]"; fi
fi

# ---------------------------------------------------------------------------
# 15. nothing on stderr
#
# Under `make test-asan` this is where a sanitizer report lands, and a report
# that does not happen to kill the process would otherwise go unnoticed.
# Under an ordinary build both logs must simply be empty: this server has no
# reason to say anything.
# ---------------------------------------------------------------------------
if grep -qE 'AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|runtime error|SUMMARY:' \
         "$TD/log" "$TD/log2" 2>/dev/null; then
	bad 'stderr: no sanitizer diagnostics' \
	    "$(grep -hE -m5 'AddressSanitizer|LeakSanitizer|runtime error|SUMMARY:' "$TD/log" "$TD/log2")"
elif [ -s "$TD/log" ] || [ -s "$TD/log2" ]; then
	bad 'stderr: both servers stayed quiet' \
	    "$(head -c 400 "$TD/log")$(head -c 400 "$TD/log2")"
else
	ok 'stderr: both servers stayed quiet'
fi

# ---------------------------------------------------------------------------
# the server is still alive after everything above
# --------------------------------------------------- the refusals, in full
# Every assertion above checks a refusal's status code. None checked the rest
# of the response -- so stripping the reason phrase, the Content-Type and the
# whole body out of `reply()` left 226 passed, 0 failed. These check what
# reply() actually sends: the reason phrase in the status line, the
# "CODE reason" body, a Content-Length that matches it, and text/plain.
#
# Only the codes curl can provoke on its own are here; the ones that need a
# hand-built request (400, 408, 501, 505) are driven through traw elsewhere
# and reach the same reply().
terr 'refusal in full: 404' 404 'Not Found'            /nope.txt
terr 'refusal in full: 403' 403 'Forbidden'            /.hidden
terr 'refusal in full: 405' 405 'Method Not Allowed'   / -X POST
terr 'refusal in full: 413' 413 'Content Too Large'    /ok.txt -X GET \
	-H 'Content-Length: 2097152' --data-binary @"$TD/2mb"

# ---------------------------------------------------------------------------
if kill -0 "$SRV" 2>/dev/null; then ok 'server: still running'
else bad 'server: still running' "it died; stderr: $(cat "$TD/log")"; fi

printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]
