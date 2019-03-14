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

	hexdump(buff, buff_size);
}
