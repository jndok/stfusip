//
//  rnr_macho.h
//  ropnroll_final
//
//  Created by jndok on 26/11/15.
//  Copyright © 2015 jndok. All rights reserved.
//

#ifndef rnr_macho_h
#define rnr_macho_h

#include <stdlib.h>
#include <string.h>

#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include <sys/queue.h>

#include "../types.h"

/* SYMTAB entry */
struct symbol_table_entry {
    SLIST_ENTRY(symbol_table_entry) chain;
    union {
        uint32_t n_strx;
    } n_un;
    uint8_t n_type;
    uint8_t n_sect;
    uint16_t n_desc;
    uint64_t n_value;

    char *sym_name;
};

SLIST_HEAD(symbol_table_head, symbol_table_entry);

__attribute__((always_inline)) struct mach_header_64 *find_mach_header_in_map(gadget_map_t *map);
__attribute__((always_inline)) struct load_command *find_load_command_in_map(gadget_map_t *map, uint32_t cmd);
__attribute__((always_inline)) struct segment_command_64 *find_segment_in_map(gadget_map_t *map, const char *segname);
__attribute__((always_inline)) struct section_64 *find_section_in_segment_in_map(struct segment_command_64 *seg, const char *sectname);

__attribute__((always_inline)) struct symtab_command *find_symbol_table_in_map(gadget_map_t *map);
__attribute__((always_inline)) struct dysymtab_command *find_dynamic_symbol_table_in_map(gadget_map_t *map);

/***/

struct symbol_table_head map_symbol_table(gadget_map_t *map);

#endif /* rnr_macho_h */
