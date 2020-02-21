#ifndef ONE4ALL
// version
#define ONE4ALL 1

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

////////////////
//            //
// Data types //
//            //
////////////////

typedef void* void_ptr;
typedef const void* const_void_ptr;
typedef void* (*shellcode_t)();

#ifndef WIN32
// Windows compatable types
#define CHAR    int8_t
#define BYTE    uint8_t
#define UCHAR   uint8_t
#define SHORT   int16_t
#define USHORT  uint16_t
#define DWORD   uint32_t
#define LONG    int32_t
#define ULONG   uint32_t
#define QWORD   uint64_t
#define SIZE    size_t
#define PVOID   void_ptr
#define LPVOID  void_ptr
#define LPCVOID const_void_ptr
#endif

// IDA types
#ifndef __int8
#define __int8 char
#endif

#ifndef __int64
#define __int64 int64_t
#endif

#ifndef _DWORD
#define _DWORD  uint32_t
#endif

#define _BYTE  uint8_t

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
#endif

///////////////////
//               //
// Useful macros //
//               //
///////////////////

#define ALIGN_TO(V, A) (((V) / (A) + 1) * (A))

///////////////////////////
//                       //
// Function Definiations //
//                       //
///////////////////////////

int memprotect(void *mem, size_t size, uint32_t prot);
void* memmap(void *addr, size_t size, uint32_t prot);
int memunmap(void *addr, size_t size);

#define xxd(X) puts(#X); hexdump(X, sizeof(X))
#define zfill(X) memset(X, 0, sizeof(X))

void hexdump_ex(const void *ptr, size_t size, intptr_t addr, void (*cb)(void *, const char *), void *ctx);
void hexdump_file(const void *data, size_t size, FILE *target);
void hexdump(const void *data, size_t size);
char *hexdump_string(const void *data, size_t size, char *buff, size_t buff_size);
size_t hexdecode(const char *encoded, void *buffer);
int fsize(FILE *fp, size_t *out);
int readfile(const char *filename, uint8_t **out_buffer, size_t *out_size);
int writefile(const char *filename, void *buffer, size_t size);


/*** SPLITTER FOR DEFINIATION AND IMPLEMENTATION ****/


///////////////////////////
//                       //
// OS specific functions //
//                       //
///////////////////////////

uint32_t _native_mem_prot_conv(uint32_t prot)
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
	return O_STATUS(VirtualProtect(mem, size, _native_mem_prot_conv(prot), &old_prot) != 0);
#endif
#ifdef LINUX
	return O_STATUS(mprotect(mem, size, _native_mem_prot_conv(prot)) == 0);
#endif

	return O_FAILED;
}

void* memmap(void *addr, size_t size, uint32_t prot)
{
#ifdef WIN32
	return VirtualAlloc(addr, size, MEM_RESERVE | MEM_COMMIT, _native_mem_prot_conv(prot));
#endif
#ifdef LINUX
	return mmap(addr, size, _native_mem_prot_conv(prot), /*flags*/ MAP_PRIVATE | MAP_ANONYMOUS, /*fd*/ 0, /*offset*/ 0);
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

#define HEX_DIGIT_DECODE(H) (('0' <= (H) && (H) <= '9') ? (H) - '0' : (((H) | ' ') - 'a' + 0xa))

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
	hexdump_file(buff, 128, stdout);

	assert(writefile("test.tmp", buff, 64) == O_SUCCESS);
	BYTE *ptr;
	size_t sz;
	assert(readfile("test.tmp", &ptr, &sz) == O_SUCCESS);

	hexdump(ptr, sz);

	assert(memunmap(data, 0x1000) == O_SUCCESS);
}
#endif
#endif
