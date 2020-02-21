void hexdump_ex(const void *ptr, size_t size, intptr_t addr, void (*cb)(void *, const char *), void *ctx);
void hexdump_file(const void *data, size_t size, FILE *target);
void hexdump(const void *data, size_t size);
char *hexdump_string(const void *data, size_t size, char *buff, size_t buff_size);
size_t hexdecode(const char *encoded, void *buffer);

#define xxd(X) puts(#X); hexdump(X, sizeof(X))
#define zfill(X) memset(X, 0, sizeof(X))

#define HEX_DIGIT_DECODE(H) (('0' <= (H) && (H) <= '9') ? (H) - '0' : (((H) | ' ') - 'a' + 0xa))
