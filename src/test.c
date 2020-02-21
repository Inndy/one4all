#ifdef ONE4ALL_TEST
int main()
{
	void* data = memmap(NULL, 0x1000, O_MEM_RWE);
	memcpy(data, "\x33\xc0\xc3", 3); // zero out eax and return for x86 / amd64
	assert(data != NULL);
	assert(((shellcode_t)data)() == 0);

	char buff[1024];
	zfill(buff); // zero fill buffer

	char *p = hexdump_string(data, 16, buff, sizeof buff);
	strcat(p, "NotBad\n");
	puts(buff);
	puts("hexdmup_file:");
	hexdump_file(buff, 128, stdout);

	assert(writefile("test-file.tmp", buff, 64) == O_SUCCESS);
	BYTE *ptr;
	size_t sz;
	assert(readfile("test-file.tmp", &ptr, &sz) == O_SUCCESS);

	puts("hexdmup:");
	hexdump(ptr, sz);
	free(ptr);

	assert(memunmap(data, 0x1000) == O_SUCCESS);

	memset(buff, 0xcc, sizeof(buff));
	size_t n = hexdecode("11 22 33 44 55 66 77 8899aa bb\ncc\tdd\reeff", (void*)&buff);
	hexdump(buff, (n | 0xf) + 1);

	PHTBL t = htbl_create(16, sizeof(int));

	for(int i = 0; i < 16; i++) {
		htbl_insert(t, &i, (void*)(uintptr_t)i);
	}

	for(int i = 0; i < t->count; i++) {
		int c = 0;
		PHTBL_ENTRY node = t->table[i];
		while(node) {
			// printf(" - %d\n", (int)node->data);
			c++;
			node = node->next;
		}
		printf("table[%d] -> %d\n", i, c);
	}
}
#endif
