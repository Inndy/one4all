#ifndef ONE4ALL
// version
#define ONE4ALL 1

#include <assert.h>
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
#define __int8 uint8_t
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

#define xxd(X) puts(#X); hexdump(X, sizeof(X));
#define zf(X) memset(X, 0, sizeof(X));

void hexdump_file(const void *data, size_t size, FILE *target) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		if(i % 16 == 0) {
			fprintf(target, "%.8llx: ", (unsigned long long)i);
		}
		fprintf(target, "%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			if ((i+1) % 16 == 0) {
				fprintf(target, " %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					fprintf(target, " ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					fprintf(target, "   ");
				}
				fprintf(target, " %s \n", ascii);
			}
		}
	}
}

void hexdump(const void *data, size_t size)
{
	hexdump_file(data, size, stdout);
}

char *hexdump_string(const void *data, size_t size, char *buff, size_t buff_size)
{
	size_t written = 0;
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size && written < buff_size; ++i) {
		if(i % 16 == 0) {
			written += snprintf(buff + written, buff_size - written, "%.8llx: ", (unsigned long long)i);
		}
		written += snprintf(buff + written, buff_size - written, "%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			if ((i+1) % 16 == 0) {
				written += snprintf(buff + written, buff_size - written, " %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					written += snprintf(buff + written, buff_size - written, " ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					written += snprintf(buff + written, buff_size - written, "   ");
				}
				written += snprintf(buff + written, buff_size - written, " %s \n", ascii);
			}
		}
	}

	return buff + written;
}

size_t hexdecode(const char *encoded, uint8_t *buffer)
{
	size_t i = 0;
	while(encoded[0] && encoded[1]) {
		char tmp[4] = {0, 0, 0, 0};
		memcpy(tmp, encoded, 2);
		buffer[i++] = strtol(tmp, NULL, 16);
		encoded += 2;
	}
}

// TODO: handle file size larger than uint32_t under 32bit process
size_t fsize(FILE *fp)
{
	size_t curr = ftell(fp);
	fseek(fp, 0, SEEK_END);
	size_t size = ftell(fp);
	fseek(fp, curr, SEEK_SET);
	return size;
}

int readfile(char *filename, uint8_t **out_buffer, size_t *out_size)
{
	FILE *fp = fopen(filename, "rb");
	if(fp == NULL) {
		return O_FAILED;
	}

	*out_size = fsize(fp);
	*out_buffer = malloc(*out_size);
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

int writefile(char *filename, void *buffer, size_t size)
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
	zf(buff); // zero fill buffer

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
