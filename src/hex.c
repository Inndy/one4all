void hexdump_ex(const void *ptr, size_t size, intptr_t addr, void (*cb)(void *, const char *), void *ctx)
{
    const uint8_t *buffer = (const uint8_t *)ptr;

	while(size > 0) {
        uint32_t written;
        char line[128];
		written = snprintf(line, sizeof(line), "%.8" PRIx64 ": ", (uint64_t)addr);

		uint32_t bound = (size >= 16) ? 16 : size;
		int i;
		for(i = 0; i < bound; i++) {
			written += snprintf(line + written, sizeof(line) - written, "%.2x ", buffer[i]);
		}
		for(; i < 16; i++) {
			written += snprintf(line + written, sizeof(line) - written, "   ");
		}
		for(i = 0; i < bound; i++) {
			written += snprintf(line + written, sizeof(line) - written, "%c", (0x20 <= buffer[i] && buffer[i] <= 0x7e) ? buffer[i] : '.');
		}

        cb(ctx, line);

		if(size <= 16) {
			return;
		}

		buffer += 16;
		size -= 16;
		addr += 16;
	}
}

void hexdump_cb_file(void *ctx, const char *data)
{
	fprintf(ctx, "%s\n", data);
}

void hexdump_file(const void *data, size_t size, FILE *target)
{
	hexdump_ex(data, size, (intptr_t)data, hexdump_cb_file, target);
}

void hexdump(const void *data, size_t size)
{
	hexdump_file(data, size, stdout);
}

void hexdump_cb_string(void *ctx, const char *data)
{
	uintptr_t *x = ctx;
	x[1] += snprintf((char*)x[0] + x[1], x[2] - x[1], "%s\n", data);
}

char *hexdump_string(const void *data, size_t size, char *buff, size_t buff_size)
{
	uintptr_t ctx[] = { (uintptr_t)buff, 0, buff_size };
	hexdump_ex(data, size, (uintptr_t)data, hexdump_cb_string, &ctx);
	return buff;
}


size_t hexdecode(const char *encoded, void *buffer)
{
	size_t i = 0;

	goto skip_space;
	while(isxdigit(encoded[0]) && isxdigit(encoded[1])) {
		((uint8_t*)buffer)[i++] = HEX_DIGIT_DECODE(encoded[0]) << 4 | HEX_DIGIT_DECODE(encoded[1]);
		encoded += 2;

skip_space:
		while(*encoded && isspace(*encoded)) encoded++;
	}

	return i;
}
