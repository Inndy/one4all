#include "../one4all.h"

int main(int argc, char *argv[])
{
	if(argc <= 1) {
		printf("Usage: %s shellcode.bin\n", argv[0]);

		const char *shellcode_hex = "48b83412341290909090c3";
		char buff[128];
		hexdecode(shellcode_hex, buff);
		writefile("sample-shellcode.bin", buff, strlen(shellcode_hex) / 2);
		return 1;
	}

	uint8_t *buff;
	size_t buff_size, map_size;
	shellcode_t shellcode_mem;

	MUST(readfile(argv[1], &buff, &buff_size));
	map_size = ALIGN_TO(buff_size, 0x1000);

	assert(shellcode_mem = memmap(NULL, map_size, O_MEM_RW));
	memcpy(shellcode_mem, buff, buff_size);
	MUST(memprotect(shellcode_mem, map_size,
				/* self-modify code? */ getenv("SHELLCODE_SMC") ? O_MEM_RWE : O_MEM_RE));

	free(buff);

	printf("shellcode returned %p\n", shellcode_mem());
	MUST(memunmap(shellcode_mem, ALIGN_TO(buff_size, 0x1000)));
	exit(0);
}
