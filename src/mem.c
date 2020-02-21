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
