//
//  rnr_gadgets.c
//  ropnroll_final
//
//  Created by jndok on 27/11/15.
//  Copyright © 2015 jndok. All rights reserved.
//

#include "rnr_gadgets.h"

__attribute__((always_inline)) uint32_t rnr_calculate_gadget_size(gadget_t gadget)
{
    char *byte = (char*)gadget;
    uint32_t sz;

    for (sz=0; *(uint8_t*)(byte+sz) != 0xc3; ++sz);

    return sz+1;
}

__attribute__((always_inline)) void rnr_dump_gadget(gadget_t gadget, gadget_size_t gadget_size)
{
    uint32_t ret=0;
    csh handle;

    ret=cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    if (ret!=CS_ERR_OK)
        return;

    cs_insn *insn;
    uint64_t count = cs_disasm(handle, (uint8_t*)gadget, gadget_size, 0x0, 0, &insn);
    for (uint32_t i=0; i<count; ++i) {
        printf("%s %s\n", insn[i].mnemonic, insn[i].op_str);
    }

}

__attribute__((always_inline)) uint64_t rnr_locate_gadget_in_map(gadget_map_t *map, gadget_t gadget, gadget_size_t sz)
{
    if (!map->map)
        return 0;

    void *loc = memmem(map->map, map->map_size, gadget, sz);
    if (!loc)
        return 0;

    uint64_t ret=loc-map->map;

    return ret;
}

__attribute__((always_inline)) uint64_t *rnr_locate_gadget_group_in_map(gadget_map_t *map, gadget_t gadget, gadget_size_t sz, uint32_t occurrences)
{
    uint64_t *arr=(uint64_t*)malloc(sizeof(uint64_t)*occurrences);
    bzero(arr, sizeof(uint64_t)*occurrences);

    void *base = map->map;
    size_t base_size=map->map_size;
    void *p1=NULL;
    uint64_t off=0;
    for (uint32_t i=0; i<occurrences; ++i) {
        p1=memmem(base+off, base_size-off, (gadget_t)gadget, sz);
        if (p1) {
            off=p1-base+1;
            arr[i]=(uint64_t)(p1-(map->map));
        }
    }

    return arr;
}
