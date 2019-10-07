
#include "kernel_utils.h"

uint64_t __readmsr(uint32_t __register) {
	// Loads the contents of a 64-bit model specific register (MSR) specified in
	// the ECX register into registers EDX:EAX. The EDX register is loaded with
	// the high-order 32 bits of the MSR and the EAX register is loaded with the
	// low-order 32 bits. If less than 64 bits are implemented in the MSR being
	// read, the values returned to EDX:EAX in unimplemented bit locations are
	// undefined.
	uint32_t __edx;
	uint32_t __eax;
	__asm__ ("rdmsr" : "=d"(__edx), "=a"(__eax) : "c"(__register));
	return (((uint64_t)__edx) << 32) | (uint64_t)__eax;
}

int kpayload_jailbreak(struct thread *td, struct kpayload_jailbreak_args *args) 
{
	struct filedesc *fd;
	struct ucred *cred;
    uint8_t *kmem;
	
    // Resolve creds
    fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	void *kernel_base;
	uint8_t *kernel_ptr;
	void **got_prison0;
	void **got_rootvnode;
    void **got_hasmself;
    void **got_canmself;
    void **got_loadable;
	
    uint64_t xfast    = args->kpayload_jailbreak_info.xfast;
    uint64_t prison0  = args->kpayload_jailbreak_info.prison0;
    uint64_t rootvn   = args->kpayload_jailbreak_info.rootvn;
    uint64_t hasmself = args->kpayload_jailbreak_info.hasmself;
    uint64_t canmself = args->kpayload_jailbreak_info.canmself;
    uint64_t loadable = args->kpayload_jailbreak_info.loadable;
    
	kernel_base   = &((uint8_t *)__readmsr(0xC0000082))[-xfast];
	kernel_ptr    = (uint8_t *)kernel_base;
	
    got_prison0   = (void **)&kernel_ptr[prison0];
	got_rootvnode = (void **)&kernel_ptr[rootvn];
    got_hasmself  = (void **)&kernel_ptr[hasmself];
    got_canmself  = (void **)&kernel_ptr[canmself];
    got_loadable  = (void **)&kernel_ptr[loadable];
	
    // Disable write protection
    uint64_t cr0 = readCr0();
    writeCr0(cr0 & ~X86_CR0_WP);    
    
    // Patch sceSblACMgrHasMmapSelfCapability to return 1
	kmem = (uint8_t *)got_hasmself;
	kmem[0] = 0xB8;
	kmem[1] = 0x01;
	kmem[2] = 0x00;
	kmem[3] = 0x00;
	kmem[4] = 0x00;
	kmem[5] = 0xC3;

    // Patch sceSblACMgrIsAllowedToMmapSelf to return 1
	kmem = (uint8_t *)got_canmself;
	kmem[0] = 0xB8;
	kmem[1] = 0x01;
	kmem[2] = 0x00;
	kmem[3] = 0x00;
	kmem[4] = 0x00;
	kmem[5] = 0xC3;

    // Bypass sceSblAuthMgrIsLoadable call in vm_mmap
    kmem = (uint8_t *)got_loadable;
	kmem[0] = 0x31;
	kmem[1] = 0xC0;
	kmem[2] = 0x90;
	kmem[3] = 0x90;
    kmem[4] = 0x90;
    
    // Restore write protection
    writeCr0(cr0);

    // Escalate process to root
	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;
	
	// Escalate ucred privileges, needed for userland access to the file system (e.g mounting & decrypting files)
	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred
	
	// sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xFFFFFFFFFFFFFFFF;
	
	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcessAuthorityId = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcessAuthorityId = 0x3801000000000013; // Max access
	
	// sceSblACMgrHasSceProcessCapability for Max capability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xFFFFFFFFFFFFFFFF;
	
	return 0;
}

int kpayload_get_fw_version(void) {
    uint64_t name = 0x400000001;
    char kstring[64];
    size_t kstring_len = 64;

    sysctl((int *)&name, 2, kstring, &kstring_len, (char *)NULL, 0);
    char *split = strtok(kstring, " ");
    int split_len = strlen(split);

    int major = strtol(split + split_len - 6, (char **)NULL, 10);
    int minor = strtol(split + split_len - 3, (char **)NULL, 10);

    int fw_version = major * 100 + minor / 10;
    
	return fw_version;
}

int jailbreak(uint64_t xfast, uint64_t prison0, uint64_t rootvn, uint64_t hasmself, uint64_t canmself, uint64_t loadable) {
    struct kpayload_jailbreak_info kpayload_jailbreak_info;
	kpayload_jailbreak_info.xfast = xfast;
    kpayload_jailbreak_info.prison0 = prison0;
    kpayload_jailbreak_info.rootvn = rootvn;
    kpayload_jailbreak_info.hasmself = hasmself;
    kpayload_jailbreak_info.canmself = canmself;
    kpayload_jailbreak_info.loadable = loadable;
	kexec(&kpayload_jailbreak, &kpayload_jailbreak_info);
	return 0;
}
