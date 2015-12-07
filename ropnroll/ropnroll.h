//
//  ropnroll.h
//  ropnroll_final
//
//  Created by jndok on 14/11/15.
//  Copyright © 2015 jndok. All rights reserved.
//

/*
    The general idea is that the user will #include "ropnroll.h"
    only in his projects.
    This file will #include all other headers in subdirectories. 
*/

#ifndef ropnroll_h
#define ropnroll_h

#define KSLIDE_UNKNOWN -1

#define KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR (0)
#define KAS_INFO_MAX_SELECTOR (1)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <capstone/capstone.h>

#include "types.h" //tmp!
#include "macho/rnr_macho.h"
#include "gadgets/rnr_gadgets.h"

extern uint64_t KextUnslidBaseAddress(const char *KextBundleName);

gadget_map_t *rnr_map_file_with_path(const char *path);

__attribute__((always_inline)) uint64_t rnr_locate_symbol_in_map(gadget_map_t *map, const char *sym_name);

__attribute__((always_inline)) uint64_t rnr_locate_kernel_base(gadget_map_t *map);

__attribute__((always_inline)) uint64_t rnr_kext_base_address(const char *bundle_id);

uint64_t rnr_get_kslide(void);
__attribute__((always_inline)) uint64_t rnr_slide_kernel_pointer(uint64_t pointer, uint64_t kslide);

#endif /* ropnroll_h */
