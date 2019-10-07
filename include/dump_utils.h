#ifndef __DUMP_UTILS_H__
#define __DUMP_UTILS_H__
#pragma once

#include <ps4.h>

#include "elf64.h"

#define DT_DIR    0x000004
#define DT_REG    0x000008
#define DEC_SIZE  0x100000

typedef struct {
    int      index;
    uint64_t fileoff;
    size_t   bufsz;
    size_t   filesz;
    int      enc;
} SegmentBufInfo;

int read_decrypt_segment(int fd, uint64_t index, uint64_t offset, size_t size, uint8_t *out);
int is_segment_in_other_segment(Elf64_Phdr *phdr, int index, Elf64_Phdr *phdrs, int num);
SegmentBufInfo *parse_phdr(Elf64_Phdr *phdrs, int num, int *segBufNum);
void do_dump(char *saveFile, int fd, SegmentBufInfo *segBufs, int segBufNum, Elf64_Ehdr *ehdr);
void decrypt_and_dump_self(char *selfFile, char *saveFile);
void decrypt_self_to_elf(char *file, char *usb);
int traverse_dir(char *base, char *usb, void(*handler)(char *, char *));

#endif
