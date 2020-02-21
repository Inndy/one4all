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
