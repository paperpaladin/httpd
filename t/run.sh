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
if [ "$ST" != "curl-exit-7" ]; then ok 'port: announced port accepts'
else bad 'port: announced port accepts' 'connection refused'; fi

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
# the server is still alive after everything above
# ---------------------------------------------------------------------------
if kill -0 "$SRV" 2>/dev/null; then ok 'server: still running'
else bad 'server: still running' "it died; stderr: $(cat "$TD/log")"; fi

printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]
