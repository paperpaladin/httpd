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

# ---------------------------------------------------------------------------
# the server under test
# ---------------------------------------------------------------------------
"$HTTPD" -t 5 >"$TD/port" 2>"$TD/log" &
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
# No file server yet: every target is 404. What is asserted here is that a
# well-formed request gets a well-formed response.
tstatus 'root: 404 for now'      404 /
thdr    'root: has Date'         '^Date: [A-Z][a-z][a-z], ' /
thdr    'root: has Content-Length' '^Content-Length: [0-9]'  /

# The announced port is the port it is actually listening on -- otherwise
# every assertion above would be against some other process.
if [ "$ST" != "curl-exit-7" ]; then ok 'port: announced port accepts'
else bad 'port: announced port accepts' 'connection refused'; fi

# ---------------------------------------------------------------------------
# 2. the request line (RFC 9112 section 3)
# ---------------------------------------------------------------------------
tstatus 'method: POST is 405'     405 / -X POST
thdr    'method: 405 has Allow'   '^Allow: GET, HEAD' / -X POST
tstatus 'method: unknown is 405'  405 / -X FROBNICATE
tstatus 'version: HTTP/1.0 ok'    404 / --http1.0

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
# the buffer is 431. Both are accepted here so the assertion is about
# refusing rather than about which refusal.
LONG=$(python3 -c 'print("a" * 5000)')
tstatus 'reqline: over-long target' '414 431 400' "/$LONG"
MANY=""
i=0
while [ "$i" -lt 200 ]; do
	MANY="$MANY -H X-Pad-$i:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	i=$((i + 1))
done
# shellcheck disable=SC2086
tstatus 'reqline: over-long header section' '431 400' / $MANY

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
traw 'two identical CL is ok'   404 \
	"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n"
traw 'odd OWS round the value'  404 \
	"GET / HTTP/1.1\r\nHost:    x\t \r\nContent-Length:  0 \r\n\r\n"
traw 'lower-case field names'   404 "GET / HTTP/1.1\r\nhOsT: x\r\n\r\n"
traw 'unknown fields ignored'   404 \
	"GET / HTTP/1.1\r\nHost: x\r\nX-Whatever: ~!#\$%&'*+-.^_\`|\r\n\r\n"

# ---------------------------------------------------------------------------
# the server is still alive after everything above
# ---------------------------------------------------------------------------
if kill -0 "$SRV" 2>/dev/null; then ok 'server: still running'
else bad 'server: still running' "it died; stderr: $(cat "$TD/log")"; fi

printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]
