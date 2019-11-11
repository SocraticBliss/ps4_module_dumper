
#include "dump_utils.h"

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
        if (i != index)
            if (p->p_filesz > 0)
                if ((phdr->p_offset >= p->p_offset) && ((phdr->p_offset + phdr->p_filesz) <= (p->p_offset + p->p_filesz)))
                    return 1;
    }
    
    return 0;
}

SegmentBufInfo *parse_phdr(Elf64_Phdr *phdrs, int num, int *segBufNum)
{
    #ifdef DEBUG_SOCKET
    //printfsocket("segment num : %d\n", num);
    #endif
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
        #ifdef DEBUG_SOCKET
        printfsocket("[-] Error: Can't dump: %s\n", saveFile);
        #endif
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
            #ifdef DEBUG_SOCKET
            printfsocket("[-] Error: Can't mmap: %s\n", selfFile);
            #endif
        }
        close(fd);
    }
    else 
    {
        #ifdef DEBUG_SOCKET
        printfsocket("[-] Error: Can't open: %s\n", selfFile);
        #endif
    }
}

void decrypt_self_to_elf(char *file, char *usb)
{
    char *dot;

    // Check filename and open file
    dot = strrchr(file, '.');
    
    #ifdef DEBUG_SOCKET
    //printfsocket("Dot: %s\n", dot);
    #endif
    
    if (!dot) return;
    if (strcmp(dot, ".elf")  &&
        strcmp(dot, ".self") &&
        strcmp(dot, ".sprx")){
        return;
    }
    
    #ifdef DEBUG_SOCKET
    // Tomorrow...
    // strcmp(dot, ".sdll") &&
    // strcmp(dot, ".bin") &&
    #endif
    
    char name[1024];
    char usbdir[1024];
    
    strcpy(name, file);
    #ifdef DEBUG_SOCKET
    //printfsocket("Name: %s\n", name);
    //printfsocket("Directory: %s\n", usb);
    #endif
    snprintf(usbdir, sizeof(usbdir), "%s/%s", usb, name+2);
    
    decrypt_and_dump_self(name+1, usbdir);
}

int traverse_dir(char *base, char *usb, void(*handler)(char *, char *))
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
                #ifdef DEBUG_SOCKET
                //printfsocket("Directory: %s\n", dname);
                #endif
                if (!strcmp(dname, ".") ||
                    !strcmp(dname, "..") ||
                    !strcmp(dname, "cache0002") ||
                    !strcmp(dname, "dev") ||
                    !strcmp(dname, "mnt") ||
                    !strcmp(dname, "preinst") ||
                    !strcmp(dname, "preinst2") ||
                    !strcmp(dname, "$RECYCLE.BIN") ||
                    !strcmp(dname, "sandbox") ||
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
                
                #ifdef DEBUG_SOCKET
                //printfsocket("USB: %s\n", usbdir);
                #endif
                mkdir(usbdir, 0644);
                
                traverse_dir(name, usb, handler);
                break;
                
            case DT_REG:
                #ifdef DEBUG_SOCKET
                //printfsocket("File: %s\n", dname);
                #endif
                /*
                if (!strcmp(dname, "aacs.bin") ||
                    !strcmp(dname, "bdplus.bin") ||
                    !strcmp(dname, "dvdcps.bin")) {
                    continue;
                }*/
                
                snprintf(name, sizeof(name), "%s/%s", base, dname);
                #ifdef DEBUG_SOCKET
                //printfsocket("Name: %s\n", name);
                #endif
                handler(name, usb);
                break;
        }
    }
    closedir(dir);
    return 0;
}