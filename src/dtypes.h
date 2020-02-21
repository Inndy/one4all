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
