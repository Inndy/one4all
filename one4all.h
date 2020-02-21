// one4all.h by Inndy Lin <inndy.tw@gmail.com>
// compiled at 2020-02-21 16:39:30 +0800
#ifndef _ONE4ALL_H_
#define _ONE4ALL_H_

/* filename: src/one4all.h */

// version
#define ONE4ALL 2

#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if _WIN32 || _WIN64
    #if _WIN64
        #define PTR64
    #else
        #define PTR32
    #endif

	#ifndef WIN32
	#define WIN32
	#endif
#elif __GNUC__
    #if __x86_64__ || __ppc64__
        #define PTR64
    #else
        #define PTR32
    #endif

	#ifndef LINUX
	#define LINUX
	#endif
#elif UINTPTR_MAX > UINT_MAX
    #define PTR64
#else
    #define PTR32
#endif

/////////////////////////
//                     //
// OS specific headers //
//                     //
/////////////////////////

#ifdef WIN32
#define O_OS_EXT

#include <winsock2.h>
#include <windows.h>
#endif

#ifdef LINUX
#define O_OS_EXT

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

///////////////////////////
//                       //
// One4All shared consts //
//                       //
///////////////////////////

#define O_INVALID (intptr_t)-1
#define O_SUCCESS 1
#define O_FAILED  0
#define O_STATUS(X) (X) ? O_SUCCESS : O_FAILED
#define MUST(X) assert((X) == O_SUCCESS)
/* filename: src/dtypes.h */

typedef void* void_ptr;
typedef const void* const_void_ptr;
typedef void* (*shellcode_t)();

#ifndef WIN32
// Windows data types for non-windows platform
#define CHAR      int8_t
#define BYTE      uint8_t
#define UCHAR     uint8_t
#define SHORT     int16_t
#define USHORT    uint16_t
#define DWORD     uint32_t
#define LONG      int32_t
#define ULONG     uint32_t
#define QWORD     uint64_t
#define SIZE_T    size_t
#define PVOID     void_ptr
#define LPVOID    void_ptr
#define LPCVOID   const_void_ptr
#define DWORD_PTR uintptr_t
#endif

// IDA types
#ifndef __int8
#define __int8 char
#endif

#ifndef __int64
#define __int64 int64_t
#endif

#ifndef _DWORD
#define _DWORD uint32_t
#endif

#ifndef _BYTE
#define _BYTE uint8_t
#endif
/* filename: src/file.h */

int fsize(FILE *fp, size_t *out);
int readfile(const char *filename, uint8_t **out_buffer, size_t *out_size);
int writefile(const char *filename, void *buffer, size_t size);
/* filename: src/hashtable.h */

typedef struct _HTBL_ENTRY {
    struct _HTBL_ENTRY *next;
    void *data;
    char key[0];
} HTBL_ENTRY, *PHTBL_ENTRY;

typedef struct {
    unsigned int count;
    unsigned int key_size;
    PHTBL_ENTRY table[0];
} HTBL, *PHTBL;

PHTBL htbl_create(unsigned int count, unsigned int key_size);
void htbl_insert(PHTBL t, void *key, void *data);
void* htbl_search(PHTBL t, void *key);
int htbl_remove(PHTBL t, void *key);
void htbl_destroy(PHTBL t);
/* filename: src/hex.h */

void hexdump_ex(const void *ptr, size_t size, intptr_t addr, void (*cb)(void *, const char *), void *ctx);
void hexdump_file(const void *data, size_t size, FILE *target);
void hexdump(const void *data, size_t size);
char *hexdump_string(const void *data, size_t size, char *buff, size_t buff_size);
size_t hexdecode(const char *encoded, void *buffer);

#define xxd(X) puts(#X); hexdump(X, sizeof(X))
#define zfill(X) memset(X, 0, sizeof(X))

#define HEX_DIGIT_DECODE(H) (('0' <= (H) && (H) <= '9') ? (H) - '0' : (((H) | ' ') - 'a' + 0xa))
/* filename: src/mem.h */

#define ALIGN_TO(V, A) (((V) / (A) + 1) * (A))

#ifdef O_OS_EXT
#define O_MEM_N   0
#define O_MEM_R   1
#define O_MEM_W   2
#define O_MEM_E   4
#define O_MEM_X   O_MEM_E
#define O_MEM_RO  O_MEM_R
#define O_MEM_RE  (O_MEM_R | O_MEM_E)
#define O_MEM_RX  O_MEM_RE
#define O_MEM_RW  (O_MEM_R | O_MEM_W)
#define O_MEM_RWE (O_MEM_R | O_MEM_W | O_MEM_E)
#define O_MEM_RWX O_MEM_RWE

int memprotect(void *mem, size_t size, uint32_t prot);
void* memmap(void *addr, size_t size, uint32_t prot);
int memunmap(void *addr, size_t size);
#endif
/* filename: src/file.c */

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
/* filename: src/hashtable.c */

uintptr_t htbl_hash_data(uintptr_t seed, void* data, size_t len)
{
	unsigned char *ptr = data;
	for(size_t i = 0; i < len; i++) {
		seed = seed * 0xdead1337 - ptr[i] * 0x13579bdf + 0xf33d1ee7;
		// seed = seed ^ (seed >> 7) ^ (ptr[i] << 19);
	}
    return seed;
}

PHTBL htbl_create(unsigned int count, unsigned int key_size)
{
    PHTBL t = malloc(sizeof(HTBL) + sizeof(PHTBL_ENTRY) * count);
    t->count = count;
    t->key_size = key_size;

    for (int i = 0; i < count; i++)
        t->table[i] = NULL;

    return t;
}

void htbl_insert(PHTBL t, void *key, void *data)
{
    PHTBL_ENTRY node = malloc(sizeof(HTBL_ENTRY) + t->key_size);
    memcpy(node->key, key, t->key_size);
    node->data = data;

    uintptr_t index = htbl_hash_data(0, key, t->key_size) % t->count;
    node->next = t->table[index];
    t->table[index] = node;
}

void* htbl_search(PHTBL t, void *key)
{
    uintptr_t index = htbl_hash_data(0, key, t->key_size) % t->count;
    for (PHTBL_ENTRY node = t->table[index];
         node != NULL;
         node = node->next)
    {
        if (memcmp(node->data, key, t->key_size) == 0)
            return node->data;
    }

    return NULL;
}

int htbl_remove(PHTBL t, void *key)
{
    uintptr_t index = htbl_hash_data(0, key, t->key_size) % t->count;
    PHTBL_ENTRY prev = NULL;

    for (PHTBL_ENTRY node = t->table[index];
         node != NULL;
         node = node->next)
    {
        if (memcmp(node->data, key, t->key_size) == 0) {
            if(prev == NULL) {
                t->table[index] = node->next;
            } else {
                prev->next = node->next;
            }

            free(node);

            return 1;
        }
        prev = node;
    }

    return 0;
}

void htbl_destroy(PHTBL t)
{
    for (int i = 0; i < t->count; i++)
    {
        PHTBL_ENTRY node = t->table[i], next;
        while (node)
        {
            next = node->next;
            free(node);
            node = next;
        }
    }
    free(t);
}
/* filename: src/hex.c */

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
/* filename: src/mem.c */

#ifdef O_OS_EXT

uint32_t _o4a_native_mem_prot_conv(uint32_t prot)
{
#ifdef WIN32
	switch(prot) {
		case O_MEM_N: return PAGE_NOACCESS;
		case O_MEM_RO: return PAGE_READONLY;
		case O_MEM_RE: return PAGE_EXECUTE_READ;
		case O_MEM_RW: return PAGE_READWRITE;
		case O_MEM_RWE: return PAGE_EXECUTE_READWRITE;
		default: return O_INVALID;
	}
#endif
#ifdef LINUX
	switch(prot) {
		case O_MEM_N: return PROT_NONE;
		case O_MEM_RO: return PROT_READ;
		case O_MEM_RE: return PROT_READ | PROT_EXEC;
		case O_MEM_RW: return PROT_READ | PROT_WRITE;
		case O_MEM_RWE: return PROT_READ | PROT_WRITE | PROT_EXEC;
		default: return O_INVALID;
	}
#endif
	return O_INVALID;
}

int memprotect(void *mem, size_t size, uint32_t prot)
{
#ifdef WIN32
	DWORD old_prot;
	return O_STATUS(VirtualProtect(mem, size, _o4a_native_mem_prot_conv(prot), &old_prot) != 0);
#endif
#ifdef LINUX
	return O_STATUS(mprotect(mem, size, _o4a_native_mem_prot_conv(prot)) == 0);
#endif

	return O_FAILED;
}

void* memmap(void *addr, size_t size, uint32_t prot)
{
#ifdef WIN32
	return VirtualAlloc(addr, size, MEM_RESERVE | MEM_COMMIT, _o4a_native_mem_prot_conv(prot));
#endif
#ifdef LINUX
	return mmap(addr, size, _o4a_native_mem_prot_conv(prot), /*flags*/ MAP_PRIVATE | MAP_ANONYMOUS, /*fd*/ 0, /*offset*/ 0);
#endif

	return NULL;
}

int memunmap(void *addr, size_t size)
{
#ifdef WIN32
	return O_STATUS(VirtualFree(addr, 0 /* must be 0 if MEM_RELEASE */, MEM_RELEASE) != 0);
#endif
#ifdef LINUX
	return O_STATUS(munmap(addr, size) == 0);
#endif

	return O_FAILED;
}

#endif
/* filename: src/test.c */

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

	assert(writefile("test.tmp", buff, 64) == O_SUCCESS);
	BYTE *ptr;
	size_t sz;
	assert(readfile("test.tmp", &ptr, &sz) == O_SUCCESS);

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
