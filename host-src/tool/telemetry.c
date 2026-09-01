/* Optional binary-telemetry filtering and decoder-module loading for dc-tool. */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __MINGW32__
#include <windows.h>
typedef HMODULE dctool_module_t;
#else
#include <dlfcn.h>
typedef void *dctool_module_t;
#endif

#include "dctool-telemetry.h"
#include "telemetry.h"

#define TELEMETRY_TEXT_CHUNK       1440u
#define TELEMETRY_TEXT_FRAME_LIMIT 32768u

typedef struct telemetry_emit_context {
    int fd;
    unsigned int emitted;
    int overflow;
    dctool_telemetry_sink_fn sink;
} telemetry_emit_context_t;

static dctool_module_t telemetry_module;
static const dctool_telemetry_decoder_v1_t *telemetry_decoder;
static unsigned int telemetry_bad_frames;
static unsigned int telemetry_decode_errors;

static int telemetry_has_suffix(const char *path)
{
    const char *slash = strrchr(path, '/');
    const char *backslash = strrchr(path, '\\');
    const char *base = path;
    const char *dot;

    if(slash && slash + 1 > base)
        base = slash + 1;
    if(backslash && backslash + 1 > base)
        base = backslash + 1;
    dot = strrchr(base, '.');
    return dot && dot != base;
}

static int telemetry_has_directory(const char *path)
{
    return strchr(path, '/') != NULL || strchr(path, '\\') != NULL;
}

static dctool_module_t telemetry_module_open(const char *path)
{
#ifdef __MINGW32__
    return LoadLibraryA(path);
#else
    return dlopen(path, RTLD_NOW | RTLD_LOCAL);
#endif
}

static void telemetry_module_close(dctool_module_t module)
{
#ifdef __MINGW32__
    FreeLibrary(module);
#else
    dlclose(module);
#endif
}

static dctool_telemetry_decoder_get_v1_fn
telemetry_module_entry(dctool_module_t module)
{
    dctool_telemetry_decoder_get_v1_fn entry = NULL;
#ifdef __MINGW32__
    entry = (dctool_telemetry_decoder_get_v1_fn)(uintptr_t)
        GetProcAddress(module, DCTOOL_TELEMETRY_DECODER_ENTRY);
#else
    *(void **)(&entry) = dlsym(module, DCTOOL_TELEMETRY_DECODER_ENTRY);
#endif
    return entry;
}

static dctool_module_t telemetry_open_with_suffix(const char *path,
                                                   char *resolved,
                                                   unsigned int capacity)
{
    static const char *const suffixes[] = {
#ifdef __MINGW32__
        ".dll", ".so"
#elif defined(MACOS)
        ".dylib", ".so"
#else
        ".so"
#endif
    };
    dctool_module_t module;
    unsigned int i;

    module = telemetry_module_open(path);
    if(module)
    {
        snprintf(resolved, capacity, "%s", path);
        return module;
    }
    if(!telemetry_has_directory(path))
    {
        int n = snprintf(resolved, capacity, "./%s", path);
        if(n >= 0 && (unsigned int)n < capacity)
        {
            module = telemetry_module_open(resolved);
            if(module)
                return module;
        }
    }
    if(telemetry_has_suffix(path))
        return (dctool_module_t)0;

    for(i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); ++i)
    {
        int n = snprintf(resolved, capacity, "%s%s", path, suffixes[i]);
        if(n < 0 || (unsigned int)n >= capacity)
            continue;
        module = telemetry_module_open(resolved);
        if(module)
            return module;
        if(!telemetry_has_directory(path))
        {
            n = snprintf(resolved, capacity, "./%s%s", path, suffixes[i]);
            if(n < 0 || (unsigned int)n >= capacity)
                continue;
            module = telemetry_module_open(resolved);
            if(module)
                return module;
        }
    }
    return (dctool_module_t)0;
}

int dctool_telemetry_decoder_load(const char *path)
{
    char resolved[1024];
    dctool_telemetry_decoder_get_v1_fn get_decoder;
    const dctool_telemetry_decoder_v1_t *decoder;

    dctool_telemetry_decoder_unload();
    if(!path || !*path)
        return -1;

    telemetry_module = telemetry_open_with_suffix(
        path, resolved, (unsigned int)sizeof(resolved));
    if(!telemetry_module)
    {
        fprintf(stderr,
                "dc-tool: telemetry decoder '%s' could not be loaded; binary telemetry will be ignored\n",
                path);
        return -1;
    }

    get_decoder = telemetry_module_entry(telemetry_module);
    decoder = get_decoder ? get_decoder() : NULL;
    if(!decoder ||
       decoder->abi_version != DCTOOL_TELEMETRY_DECODER_ABI_V1 ||
       decoder->struct_size < offsetof(dctool_telemetry_decoder_v1_t, decode) +
                              sizeof(decoder->decode) ||
       !decoder->decode)
    {
        fprintf(stderr,
                "dc-tool: '%s' is not a compatible telemetry decoder (ABI %u)\n",
                resolved, DCTOOL_TELEMETRY_DECODER_ABI_V1);
        telemetry_module_close(telemetry_module);
        telemetry_module = (dctool_module_t)0;
        return -1;
    }

    telemetry_decoder = decoder;
    fprintf(stderr, "dc-tool: telemetry decoder loaded: %s (%s)\n",
            decoder->name ? decoder->name : "unnamed", resolved);
    return 0;
}

void dctool_telemetry_decoder_unload(void)
{
    telemetry_decoder = NULL;
    if(telemetry_module)
    {
        telemetry_module_close(telemetry_module);
        telemetry_module = (dctool_module_t)0;
    }
}

static void telemetry_emit(void *opaque, const char *text, uint32_t size)
{
    telemetry_emit_context_t *context = (telemetry_emit_context_t *)opaque;

    if(!context || !context->sink || !text || size == 0 || context->overflow)
        return;
    if(size > TELEMETRY_TEXT_FRAME_LIMIT - context->emitted)
    {
        context->overflow = 1;
        return;
    }
    context->emitted += size;
    while(size)
    {
        unsigned int chunk = size > TELEMETRY_TEXT_CHUNK ?
                             TELEMETRY_TEXT_CHUNK : (unsigned int)size;
        context->sink(context->fd, (const unsigned char *)text, chunk);
        text += chunk;
        size -= chunk;
    }
}

static void telemetry_notice(int fd, dctool_telemetry_sink_fn sink,
                             const char *what, unsigned int count)
{
    char message[144];
    int n;

    if(!sink || (count != 1 && (count & 63u) != 0))
        return;
    n = snprintf(message, sizeof(message),
                 "dc-tool: %s telemetry frame (count=%u)\n", what, count);
    if(n > 0)
    {
        unsigned int size = (unsigned int)n;
        if(size >= sizeof(message))
            size = (unsigned int)sizeof(message) - 1u;
        sink(fd, (const unsigned char *)message, size);
    }
}

static int telemetry_frame_valid(const unsigned char *data, unsigned int size)
{
    uint16_t payload_size;
    uint32_t expected_crc;

    if(size < DCTOOL_TELEMETRY_HEADER_SIZE ||
       size > DCTOOL_TELEMETRY_FRAME_MAX ||
       data[DCTOOL_TELEMETRY_OFF_VERSION] !=
           DCTOOL_TELEMETRY_WIRE_VERSION ||
       data[DCTOOL_TELEMETRY_OFF_HEADER_SIZE] !=
           DCTOOL_TELEMETRY_HEADER_SIZE ||
       data[DCTOOL_TELEMETRY_OFF_FLAGS] != 0 ||
       data[DCTOOL_TELEMETRY_OFF_KIND] == 0)
        return 0;

    payload_size = dctool_telemetry_read_le16(
        data + DCTOOL_TELEMETRY_OFF_PAYLOAD_SIZE);
    if((unsigned int)payload_size + DCTOOL_TELEMETRY_HEADER_SIZE != size)
        return 0;
    expected_crc = dctool_telemetry_read_le32(
        data + DCTOOL_TELEMETRY_OFF_CRC32);
    return expected_crc == dctool_telemetry_frame_crc32(data, size);
}

int dctool_telemetry_filter(int fd,
                            const unsigned char *data,
                            unsigned int declared_size,
                            unsigned int packet_size,
                            dctool_telemetry_sink_fn sink)
{
    telemetry_emit_context_t context;
    int result;

    if(!data || packet_size < 4 ||
       memcmp(data, DCTOOL_TELEMETRY_MAGIC, 4) != 0)
        return 0;

    /* Never leak a binary-looking frame to the terminal. A valid frame is
     * intentionally consumed even when no optional decoder was requested. */
    if(declared_size != packet_size ||
       !telemetry_frame_valid(data, declared_size))
    {
        telemetry_bad_frames++;
        telemetry_notice(fd, sink, "rejected", telemetry_bad_frames);
        return 1;
    }
    if(!telemetry_decoder)
        return 1;

    context.fd = fd;
    context.emitted = 0;
    context.overflow = 0;
    context.sink = sink;
    result = telemetry_decoder->decode(
        data, declared_size, telemetry_emit, &context);
    if((result != DCTOOL_TELEMETRY_DECODE_OK &&
        result != DCTOOL_TELEMETRY_DECODE_IGNORE) || context.overflow)
    {
        telemetry_decode_errors++;
        telemetry_notice(fd, sink,
                         context.overflow ? "oversized decoded" : "decoder-error",
                         telemetry_decode_errors);
    }
    return 1;
}
