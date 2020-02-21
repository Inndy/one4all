// TODO: handle file size larger than uint32_t under 32bit process
int fsize(FILE *fp, size_t *out)
{
	off_t curr = ftello(fp);
	if(fseeko(fp, 0, SEEK_END) != 0) return O_FAILED;
	*out = ftello(fp);
	// it will be a fatal error if we can't restore file pointer
	assert(fseeko(fp, curr, SEEK_SET) == 0);
	return O_SUCCESS;
}

int readfile(const char *filename, uint8_t **out_buffer, size_t *out_size)
{
	FILE *fp = fopen(filename, "rb");
	if(fp == NULL) {
		return O_FAILED;
	}

	if(fsize(fp, out_size) != O_SUCCESS) {
		goto failed;
	}

	*out_buffer = (uint8_t*)malloc(*out_size);
	if(*out_buffer == NULL) {
		goto failed;
	}

	if(fread(*out_buffer, *out_size, 1, fp) != 1) {
		goto failed;
	}

	fclose(fp);
	return O_SUCCESS;

failed:
	free(*out_buffer);
	*out_size = 0;
	*out_buffer = NULL;
	fclose(fp);
	return O_FAILED;
}

int writefile(const char *filename, void *buffer, size_t size)
{
	FILE *fp = fopen(filename, "wb");
	if(fp == NULL) {
		return O_FAILED;
	}

	if(fwrite(buffer, size, 1, fp) != 1) {
		goto failed;
	}

	fclose(fp);
	return O_SUCCESS;
failed:
	fclose(fp);
	return O_FAILED;
}
