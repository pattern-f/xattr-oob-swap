//
//  mycommon.h
//  ios-fuzzer
//
//  Created by Quote on 2021/1/26.
//  Copyright © 2021 Quote. All rights reserved.
//

#ifndef mycommon_h
#define mycommon_h

#include <stdint.h>
#include <stdbool.h>

#define arrayn(array) (sizeof(array)/sizeof((array)[0]))

#define KB  (1024u)
#define MB  (1024u * KB)
#define GB  (1024u * MB)

// this macro can be used as a suffix for declarations/definitions instead of qnotused()
#if defined(__clang__) || defined(__GNUC__)
# define QUNUSED  __attribute__((unused))
#else
# define QUNUSED
#endif

#define __CASSERT_N0__(l) COMPILE_TIME_ASSERT_ ## l
#define __CASSERT_N1__(l) __CASSERT_N0__(l)
#define  __CASSERT_N2__(l)  dummy_var_ ## __CASSERT_N0__(l)
#define CASSERT(cnd) typedef char __CASSERT_N1__(__LINE__)[(cnd) ? 1 : -1] QUNUSED

typedef uint64_t kptr_t; // 64 bit CPU only

struct exploit_common_s {
    bool debug;
    bool has_PAC;
    const char *model;
    const char *osversion;
    const char *osproductversion;
    const char *machine;
    const char *kern_version;

    int64_t physmemsize;
    uint64_t pagesize;

    kptr_t kernel_base;
    kptr_t kernel_task;
    kptr_t kernel_map;
    kptr_t kernel_proc;
    kptr_t self_proc;
    kptr_t self_task;
    kptr_t self_ipc_space;
    kptr_t kernel_slide;
    kptr_t text_slide;
    kptr_t data_slide;
    kptr_t zone_array;
    uint32_t num_zones;

    // old style
    uint16_t zone_ipc_ports;
    uint16_t zone_tasks;
    uint32_t fake_port;
    uint64_t fake_port_page_addr;
    uint64_t fake_task_page_addr;
    uint64_t fake_port_address;
    uint64_t fake_task_address;
    uint8_t *fake_port_page;
    uint8_t *fake_task_page;
    uint8_t *fake_port_data;
    uint8_t *fake_task_data;
};

extern struct exploit_common_s g_exp;

void sys_init(void);
void print_os_details(void);

#endif /* mycommon_h */
