//
//  kapi_memory.c
//  ios-fuzzer
//
//  Created by Quote on 2021/1/22.
//  Copyright © 2021 Quote. All rights reserved.
//

#include <mach/mach_error.h>
#include <mach/vm_map.h>
#include "mycommon.h"
#include "kapi.h"
#include "utils.h"

mach_port_t kernel_task_port;

void (^stage0_read)(kptr_t addr, void *data, size_t len);
uint32_t (^stage0_read32)(kptr_t addr);
uint64_t (^stage0_read64)(kptr_t addr);
kptr_t (^stage0_read_kptr)(kptr_t addr);

bool (^stage0_write)(kptr_t addr, void *data, size_t len);
bool (^stage0_write64)(kptr_t addr, uint64_t v);

void kapi_read(kptr_t addr, void *data, size_t len)
{
    if (!kernel_task_port) {
        return stage0_read(addr, data, len);
    }
    kern_return_t kr;
    vm_size_t outsize = len;

    kr = vm_read_overwrite(kernel_task_port, addr, len, (vm_address_t)data, &outsize);
    if (kr != KERN_SUCCESS) {
        util_error("%s: kr %d: %s", __func__, kr, mach_error_string(kr));
    }
}

uint32_t kapi_read32(kptr_t addr)
{
    if (!kernel_task_port) {
        return stage0_read32(addr);
    }
    uint32_t v = 0;
    kern_return_t kr;
    vm_size_t outsize = sizeof(v);

    kr = vm_read_overwrite(kernel_task_port, addr, outsize, (vm_address_t)&v, &outsize);
    if (kr != KERN_SUCCESS) {
        util_error("%s: kr %d: %s", __func__, kr, mach_error_string(kr));
    }
    return v;
}

uint64_t kapi_read64(kptr_t addr)
{
    if (!kernel_task_port) {
        return stage0_read64(addr);
    }
    uint64_t v = 0;
    kern_return_t kr;
    vm_size_t outsize = sizeof(v);

    kr = vm_read_overwrite(kernel_task_port, addr, outsize, (vm_address_t)&v, &outsize);
    if (kr != KERN_SUCCESS) {
        util_error("%s: kr %d: %s", __func__, kr, mach_error_string(kr));
    }
    return v;
}

kptr_t kapi_read_kptr(kptr_t addr)
{
    if (!kernel_task_port) {
        return stage0_read_kptr(addr);
    }
    kptr_t v = 0;
    kern_return_t kr;
    vm_size_t outsize = sizeof(v);

    kr = vm_read_overwrite(kernel_task_port, addr, outsize, (vm_address_t)&v, &outsize);
    if (kr != KERN_SUCCESS) {
        util_error("%s: kr %d: %s", __func__, kr, mach_error_string(kr));
    }
    return v;
}

bool kapi_write(kptr_t addr, void *data, size_t len)
{
    if (!kernel_task_port) {
        return stage0_write(addr, data, len);
    }
    kern_return_t kr;
    mach_msg_type_number_t size = (mach_msg_type_number_t)len;

    kr = vm_write(kernel_task_port, addr, (vm_address_t)data, size);
    if (kr != KERN_SUCCESS) {
        util_error("%s: kr %d: %s", __func__, kr, mach_error_string(kr));
        return false;
    }
    return true;
}

bool kapi_write32(kptr_t addr, uint32_t value)
{
    if (!kernel_task_port) {
        return stage0_write(addr, &value, sizeof(value));
    }
    return kapi_write(addr, &value, sizeof(value));
}

bool kapi_write64(kptr_t addr, uint64_t value)
{
    if (!kernel_task_port) {
        return stage0_write64(addr, value);
    }
    return kapi_write(addr, &value, sizeof(value));
}

kptr_t kapi_vm_allocate(size_t len)
{
    kern_return_t kr;
    vm_address_t address = 0;

    kr = vm_allocate(kernel_task_port, (vm_address_t *)&address, len, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        util_error("%s: kr %d: %s", __func__, kr, mach_error_string(kr));
    }
    return address;
}
