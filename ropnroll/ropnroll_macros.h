//
//  ropnroll_macros.h
//  ropnroll_final
//
//  Created by jndok on 25/11/15.
//  Copyright © 2015 jndok. All rights reserved.
//

#ifndef ropnroll_macros_h
#define ropnroll_macros_h

#include "ropnroll.h"

extern uint64_t kslide;

#define RNR_SET_SLIDE(val) kslide=val;
#define RNR_SLIDE_POINTER(ptr) rnr_slide_kernel_pointer(ptr, kslide)

#endif /* ropnroll_macros_h */
