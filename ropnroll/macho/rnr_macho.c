//
//  rnr_macho.c
//  ropnroll_final
//
//  Created by jndok on 26/11/15.
//  Copyright © 2015 jndok. All rights reserved.
//

#include "rnr_macho.h"

__attribute__((always_inline)) struct mach_header_64 *find_mach_header_in_map(gadget_map_t *map)
{
    struct mach_header_64 *header = (struct mach_header_64*)map->map;
    if (header->magic != MH_MAGIC_64)
        return NULL;

    return header;
}

__attribute__((always_inline)) struct load_command *find_load_command_in_map(gadget_map_t *map, uint32_t cmd)
{
    struct mach_header_64 *header = find_mach_header_in_map(map);

    struct load_command *lcmd = ((void*)header + sizeof(struct mach_header_64));
    for (uint32_t i=0; i<header->ncmds; ++i) {
        if (lcmd->cmd==cmd) {
            return lcmd;
        }

        lcmd = ((void*)lcmd + lcmd->cmdsize);
    }

    return NULL;
}

__attribute__((always_inline)) struct segment_command_64 *find_segment_in_map(gadget_map_t *map, const char *segname)
{
    return (struct segment_command_64*)find_load_command_in_map(map, LC_SEGMENT_64);
}

__attribute__((always_inline)) struct section_64 *find_section_in_segment_in_map(struct segment_command_64 *seg, const char *sectname)
{
    if (!seg)
        return NULL;

    struct section_64 *sec=(struct section_64*)((void*)seg+sizeof(struct segment_command_64));
    for (uint32_t i=0; i<seg->nsects; ++i) {
        if (strcmp(sec->sectname, sectname) == 0) {
            return sec;
        }

        sec = ((void*)sec + sizeof(struct section_64));
    }

    return NULL;
}

__attribute__((always_inline)) struct symtab_command *find_symbol_table_in_map(gadget_map_t *map)
{
    return (struct symtab_command *)find_load_command_in_map(map, LC_SYMTAB);
}

__attribute__((always_inline)) struct dysymtab_command *find_dynamic_symbol_table_in_map(gadget_map_t *map)
{
    return (struct dysymtab_command *)find_load_command_in_map(map, LC_DYSYMTAB);
}

/***/

struct symbol_table_head map_symbol_table(gadget_map_t *map)
{
    struct symbol_table_head head = SLIST_HEAD_INITIALIZER(head);
    struct symbol_table_entry *old=NULL;

    struct mach_header_64 *header=find_mach_header_in_map(map);
    struct symtab_command *sym_cmd=find_symbol_table_in_map(map);
    void *symtable=(void*)header+sym_cmd->symoff;
    void *strtable=(void*)header+sym_cmd->stroff;

    struct nlist_64 *entry=(struct nlist_64*)symtable;

    SLIST_INIT(&head);

    for (uint32_t i=0; i<sym_cmd->nsyms; ++i) {
        struct symbol_table_entry *curr=(struct symbol_table_entry*)malloc(sizeof(struct symbol_table_entry));

        curr->sym_name=strtable+(entry->n_un.n_strx);
        curr->n_un.n_strx=entry->n_un.n_strx;

        curr->n_desc=entry->n_desc;
        curr->n_sect=entry->n_sect;
        curr->n_type=entry->n_type;
        curr->n_value=entry->n_value;

        if (!old) {
            SLIST_INSERT_HEAD(&head, curr, chain);
        } else {
            SLIST_INSERT_AFTER(old, curr, chain);
        }
        old=curr;

        entry = ((void*)entry + sizeof(struct nlist_64));
    }

    return head;
}
