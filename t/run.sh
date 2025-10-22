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

# tstatus NAME WANT PATH [curl args...]
tstatus() {
	_n=$1; _w=$2; shift 2
	fetch "$@"
	if [ "$ST" = "$_w" ]; then ok "$_n"
	else bad "$_n" "want status $_w, got $ST" "$(cat "$TD/curlerr")"; fi
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
# 1. the socket is there, and it speaks HTTP/1.1
# ---------------------------------------------------------------------------
tstatus 'root: 200'              200 /
thdr    'root: content-length'   '^Content-Length: 6'  /
tbody   'root: body'             'httpd'               /

# The announced port is the port it is actually listening on -- otherwise
# every assertion above would be against some other process.
if [ "$ST" != "curl-exit-7" ]; then ok 'port: announced port accepts'
else bad 'port: announced port accepts' 'connection refused'; fi

# ---------------------------------------------------------------------------
# the server is still alive after everything above
# ---------------------------------------------------------------------------
if kill -0 "$SRV" 2>/dev/null; then ok 'server: still running'
else bad 'server: still running' "it died; stderr: $(cat "$TD/log")"; fi

printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]
