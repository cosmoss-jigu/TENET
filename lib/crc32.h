#ifndef _CRC32_H
#define _CRC32_H

#ifdef __cplusplus
extern "C" {
#endif

uint32_t crc32_raw(const void *buf, size_t size, uint32_t crc);
uint32_t crc32(const void *buf, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* _CRC32_H */
