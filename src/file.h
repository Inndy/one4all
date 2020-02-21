int fsize(FILE *fp, size_t *out);
int readfile(const char *filename, uint8_t **out_buffer, size_t *out_size);
int writefile(const char *filename, void *buffer, size_t size);
