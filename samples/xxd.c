#include "../one4all.h"

int main(int argc, char *argv[])
{
	if(argc <= 1) {
		printf("Usage: %s file\n", argv[0]);
		return 1;
	}

	uint8_t *buff;
	size_t buff_size, map_size;

	MUST(readfile(argv[1], &buff, &buff_size));

	if(argv[2]) {
		FILE *fout = fopen(argv[2], "w");
		assert(fout != NULL);
		hexdump_file(buff, buff_size, fout);
		fclose(fout);
	} else {
		hexdump(buff, buff_size);
	}
}
