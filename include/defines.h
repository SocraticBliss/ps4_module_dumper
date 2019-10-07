#ifndef __DEFINES_H__
#define __DEFINES_H__
#pragma once

#include "offsets.h"

#ifdef DEBUG_SOCKET
    #define printfsocket(format, ...)                            \
        do {                                                     \
            char buffer[512];                                    \
            int size = sprintf(buffer, format, ##__VA_ARGS__);   \
            sceNetSend(sock, buffer, size, 0);                   \
        } while(0)
#endif

#define SLIST_ENTRY(type)         \
struct {                          \
    struct type *sle_next;        \
}

#define SLIST_HEAD(name, type)    \
struct name {                     \
    struct type *slh_first;       \
}

#define TRACEBUF

#define TAILQ_ENTRY(type)         \
struct {                          \
    struct type *tqe_next;        \
    struct type **tqe_prev;       \
    TRACEBUF                      \
}

typedef struct {
    uint32_t props;
    uint32_t reserved;
    uint64_t offset;
    uint64_t filesz;
    uint64_t memsz;
} self_entry_t;

typedef struct {
    uint32_t magic;
    uint8_t  version;
    uint8_t  mode;
    uint8_t  endian;
    uint8_t  attr;
    uint32_t key_type;
    uint16_t header_size;
    uint16_t meta_size;
    uint64_t file_size;
    uint16_t num_entries;
    uint16_t flags;
    uint32_t reserved;
    self_entry_t entries[0];
} self_header_t;

struct knote;

struct kevent {
    uintptr_t      ident;  // identifier for this event
    short          filter; // filter for event 
    unsigned short flags;
    unsigned int   fflags;
    intptr_t       data;
    void           *udata; // opaque user data identifier
};

struct filterops {
    int    f_isfd;                           // true if ident == filedescriptor
    int    (*f_attach)(struct knote *kn);
    void   (*f_detach)(struct knote *kn);
    int    (*f_event)(struct knote *kn, long hint);
    void   (*f_touch)(struct knote *kn, struct kevent *kev, unsigned long type);
};

struct knote {
    SLIST_ENTRY(knote)   kn_link;            // for kq
    SLIST_ENTRY(knote)   kn_selnext;         // for struct selinfo
    struct               knlist *kn_knlist;  // f_attach populated
    TAILQ_ENTRY(knote)   kn_tqe;
    struct               kqueue *kn_kq;      // which queue we are on
    struct               kevent kn_kevent;
    int                  kn_status;          // protected by kq lock
    int                  kn_sfflags;         // saved filter flags
    intptr_t             kn_sdata;           // saved data field
    union {              
        struct           file *p_fp;         // file data pointer
        struct           proc *p_proc;       // proc pointer
        struct           aiocblist *p_aio;   // AIO job pointer
        struct           aioliojob *p_lio;   // LIO job pointer
    } kn_ptr;            
    struct               filterops *kn_fop;
    void                 *kn_hook;
    int                  kn_hookid;
};

SLIST_HEAD(klist, knote);

struct knlist {
    struct klist kl_list;
    void   (*kl_lock)(void *);               // lock function
    void   (*kl_unlock)(void *);
    void   (*kl_assert_locked)(void *);
    void   (*kl_assert_unlocked)(void *);
    void   *kl_lockarg;                      // argument passed to kl_lockf()
};

struct fileops {
    void *fo_read;
    void *fo_write;
    void *fo_truncate;
    void *fo_ioctl;
    void *fo_poll;
    void *fo_kqfilter;
    void *fo_stat;
    void *fo_close;
    void *fo_chmod;
    void *fo_chown;
    int  fo_flags;    // DFLAG_* below
};

#endif
