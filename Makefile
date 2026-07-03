MONITOR = tgt-monitor
RENEW   = tgt-renew

CCX64  := x86_64-w64-mingw32-gcc
CCX86  := i686-w64-mingw32-gcc
CFLAGS := -Wall -Werror -Os -s -Iinclude -D_NO_NTDLL_CRT_

.DEFAULT: all
all: monitor renew

monitor: dist/$(MONITOR).x64.o dist/$(MONITOR).x86.o
renew:   dist/$(RENEW).x64.o   dist/$(RENEW).x86.o

dist/$(MONITOR).x64.o: src/monitor.c include/common.c
	$(CCX64) -c src/monitor.c -o $@ $(CFLAGS)

dist/$(MONITOR).x86.o: src/monitor.c include/common.c
	$(CCX86) -c src/monitor.c -o $@ $(CFLAGS)

dist/$(RENEW).x64.o: src/renew.c include/common.c include/crypto.c include/asn.c
	$(CCX64) -c src/renew.c -o $@ $(CFLAGS)

dist/$(RENEW).x86.o: src/renew.c include/common.c include/crypto.c include/asn.c
	$(CCX86) -c src/renew.c -o $@ $(CFLAGS)

clean:
	rm -f dist/*.o
