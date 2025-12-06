/* fs_gs.h
 * Simple declarations for x86_64 assembly helpers to read FS/GS selector and base.
 * Functions return 0 on failure; selector functions return 16-bit value in low bits.
 */
#ifndef FS_GS_H
#define FS_GS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return lower 16-bit selector value (or 0 on failure). */
uint16_t get_fs_selector(void);
uint16_t get_gs_selector(void);

/* Return FS/GS base pointer (or 0 on failure). */
uintptr_t get_fs_base(void);
uintptr_t get_gs_base(void);

#ifdef __cplusplus
}
#endif

#endif /* FS_GS_H */
