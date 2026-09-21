# version.dll - Bandizip 7.4.6 edition patch (x86-64)
#
#   make          build dist/version.dll
#   make check    build + validate the artifact (tools/check_dll.py)
#   make clean
#
# Toolchain: x86_64-w64-mingw32-gcc (mingw-w64).

CC      := x86_64-w64-mingw32-gcc
CFLAGS  := -O2 -Wall -Wextra -municode -ffreestanding -Wno-cast-function-type \
           -fno-tree-loop-distribute-patterns
# no CRT startup: the DLL provides its own DllMainCRTStartup
LDFLAGS := -shared -nostartfiles -Wl,-e,DllMainCRTStartup \
           -Wl,--disable-auto-import -Wl,--subsystem,windows:6.0 -s

all: dist/version.dll

dist/version.dll: src/version.c src/version.def | dist
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ src/version.c src/version.def

dist:
	mkdir -p dist

check: dist/version.dll
	python3 tools/check_dll.py dist/version.dll

clean:
	rm -rf dist

.PHONY: all check clean
