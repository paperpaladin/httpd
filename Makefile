CC      ?= gcc
# -ffile-prefix-map is not optional: -g writes the compiler's working directory
# into DWARF .debug_line_str and the build stops being byte-reproducible.
CFLAGS  ?= -std=c11 -g -O2 -Wall -Wextra -Wpedantic -D_FORTIFY_SOURCE=2 \
           -fstack-protector-strong -ffile-prefix-map=$(CURDIR)=.

all: httpd

httpd: httpd.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test: all
	@t/run.sh

# Every byte of a request is untrusted input, and this program parses it with
# pointer arithmetic over a fixed buffer. The whole suite has to pass with
# the sanitizers on, not a subset of it.
#
# halt_on_error for UBSan is load-bearing: without it, UBSan prints a
# diagnostic and carries on with whatever value the undefined operation
# produced, so the suite would go green with a signed overflow in it. ASan's
# own default already aborts.
#
# The suite's last assertion greps both servers' stderr for sanitizer
# diagnostics, so a report that does not happen to kill the process still
# fails the run. And httpd exits cleanly on SIGTERM precisely so that
# LeakSanitizer -- which only runs at normal exit -- gets to run at all.
SANFLAGS = -std=c11 -g -O1 -fsanitize=address,undefined \
           -fno-omit-frame-pointer -Wall -Wextra -Wpedantic \
           -ffile-prefix-map=$(CURDIR)=.
SANOPT   = ASAN_OPTIONS=detect_leaks=1 \
           UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1

test-asan: httpd.c
	$(CC) $(SANFLAGS) -o httpd-san httpd.c $(LDFLAGS)
	@$(SANOPT) t/run.sh $(CURDIR)/httpd-san

clean:
	rm -f httpd httpd-san
	rm -rf t/tmp

.PHONY: all test test-asan clean
