PROJECT = tgt-monitor
SRCS    := src/main.c src/utils.c

CCX64  := x86_64-w64-mingw32-gcc
CCX86  := i686-w64-mingw32-gcc
LDX64  := x86_64-w64-mingw32-ld
LDX86  := i686-w64-mingw32-ld
CFLAGS := -Wall -Werror -Os -s -Iinclude -D_NO_NTDLL_CRT_

.DEFAULT: all
all: bof

bof: $(PROJECT).x64.o $(PROJECT).x86.o

$(PROJECT).x64.o: $(SRCS)
	$(CCX64) -c src/main.c  -o dist/main.x64.o  $(CFLAGS)
	$(CCX64) -c src/utils.c -o dist/utils.x64.o $(CFLAGS)
	$(LDX64) -r -o dist/$@ dist/main.x64.o dist/utils.x64.o
	@rm dist/main.x64.o dist/utils.x64.o

$(PROJECT).x86.o: $(SRCS)
	$(CCX86) -c src/main.c  -o dist/main.x86.o  $(CFLAGS)
	$(CCX86) -c src/utils.c -o dist/utils.x86.o $(CFLAGS)
	$(LDX86) -r -o dist/$@ dist/main.x86.o dist/utils.x86.o
	@rm dist/main.x86.o dist/utils.x86.o

clean:
	rm -f dist/$(PROJECT).x64.o dist/$(PROJECT).x86.o