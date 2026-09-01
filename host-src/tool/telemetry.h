#ifndef DCTOOL_TELEMETRY_HOST_H
#define DCTOOL_TELEMETRY_HOST_H

typedef void (*dctool_telemetry_sink_fn)(int fd,
                                         const unsigned char *data,
                                         unsigned int size);

int dctool_telemetry_decoder_load(const char *path);
void dctool_telemetry_decoder_unload(void);

/* Returns nonzero when data is a telemetry frame and must not be printed as
 * ordinary console bytes. */
int dctool_telemetry_filter(int fd,
                            const unsigned char *data,
                            unsigned int declared_size,
                            unsigned int packet_size,
                            dctool_telemetry_sink_fn sink);

#endif /* DCTOOL_TELEMETRY_HOST_H */
