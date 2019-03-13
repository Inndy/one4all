test:
	/usr/bin/gcc test.c -g -m32 -o test-32.elf
	/usr/bin/gcc test.c -g -m64 -o test-64.elf
	/usr/bin/i686-w64-mingw32-gcc test.c -g -m32 -o test-32.exe
	/usr/bin/x86_64-w64-mingw32-gcc test.c -g -m64 -o test-64.exe
