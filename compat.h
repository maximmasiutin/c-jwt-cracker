/*

Portability shims for platforms whose C runtime is missing a POSIX function
this program relies on.

The only case today is strndup. It is POSIX.1-2008 and is present on glibc and
on macOS, but MinGW-w64's UCRT runtime does not provide it, so a native Windows
build fails to link. Without a declaration the compiler also assumes an int
return, which truncates the pointer on a 64-bit target long before the linker
is reached.

The fallback is compiled only where strndup is genuinely absent, so it changes
nothing on the platforms that already have it.

*/

#ifndef JWTCRACK_COMPAT_H
#define JWTCRACK_COMPAT_H

#include <stddef.h>

/* MinGW does not define strndup and does not set a feature macro that would let
 * us detect it directly, so key off the toolchain. If a future MinGW gains
 * strndup, defining HAVE_STRNDUP on the command line skips this shim. */
#if defined(__MINGW32__) && !defined(HAVE_STRNDUP)

#include <stdlib.h>
#include <string.h>

static inline char *strndup(const char *s, size_t n)
{
    size_t len = strnlen(s, n);
    char *copy = (char *)malloc(len + 1);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, s, len);
    copy[len] = '\0';
    return copy;
}

#endif /* __MINGW32__ && !HAVE_STRNDUP */

#endif /* JWTCRACK_COMPAT_H */
