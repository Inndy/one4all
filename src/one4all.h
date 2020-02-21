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
