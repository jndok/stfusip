//
//  ropnroll.c
//  ropnroll_final
//
//  Created by jndok on 14/11/15.
//  Copyright © 2015 jndok. All rights reserved.
//

#include "ropnroll.h"

uint64_t flags=0;
uint64_t kslide=0x0;

gadget_map_t *rnr_map_file_with_path(const char *path)
{
    int fd=open(path, O_RDONLY);
    if (fd<0)
        return NULL;

    struct stat st;
    fstat(fd, &st);

    gadget_map_t *map=(gadget_map_t*)malloc(sizeof(gadget_map_t));
    map->map=mmap((void*)0x0, (size_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0x0);
    if (!map->map)
        return NULL;
    map->map_size=(size_t)st.st_size;

    return map;
}

__attribute__((always_inline)) uint64_t rnr_locate_symbol_in_map(gadget_map_t *map, const char *sym_name)
{
    void *symtable=NULL, *strtable=NULL;
    uint32_t nsyms=0;
    struct mach_header_64 *header = (struct mach_header_64*)map->map;
    if (header->magic != MH_MAGIC_64)
        return 0;

    struct load_command *lcmd = ((void*)header + sizeof(struct mach_header_64));
    for (uint32_t i=0; i<header->ncmds; ++i) {
        if (lcmd->cmd==LC_SYMTAB) {
            struct symtab_command *sym_cmd=(struct symtab_command*)lcmd;
            symtable=((void*)header + sym_cmd->symoff);
            strtable=((void*)header + sym_cmd->stroff);
            nsyms=sym_cmd->nsyms;

            break;
        }

        lcmd = ((void*)lcmd + lcmd->cmdsize);
    }

    struct nlist_64 *entry=(struct nlist_64*)symtable;
    for (uint32_t i=0; i<nsyms; ++i) {
        if (strcmp(strtable+(entry->n_un.n_strx), sym_name) == 0) {
            return entry->n_value;
        }
        entry=((void*)entry + sizeof(struct nlist_64));
    }

    return 0;
}

__attribute__((always_inline)) uint64_t rnr_locate_kernel_base(gadget_map_t *map)
{
    struct segment_command_64 *kernel_text=find_segment_in_map(map, SEG_TEXT);
    return kernel_text->vmaddr;
}

__attribute__((always_inline)) uint64_t rnr_kext_base_address(const char *bundle_id)
{
    return KextUnslidBaseAddress(bundle_id);
}

uint64_t rnr_get_kslide(void)
{
    if (getuid() != 0)
        return KSLIDE_UNKNOWN;

    uint64_t _kslide=0;
    uint64_t _kslide_sz=sizeof(kslide);

    syscall(SYS_kas_info, KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR, &_kslide, &_kslide_sz);

    return _kslide;
}

__attribute__((always_inline)) uint64_t rnr_slide_kernel_pointer(uint64_t pointer, uint64_t kslide)
{
    if (kslide==KSLIDE_UNKNOWN) {
        return pointer;
    } else {
        return pointer+kslide;
    }

    return 0;
}
