/*
 * str_len.c — Archetype: null-terminated string length.
 *
 * The simplest possible pointer-walking function: walk a byte pointer
 * until a zero byte is found, return the distance. Exercises Ghidra's
 * loop recovery and fun-doc's ability to identify an extremely common
 * idiom (strlen-style). Zero-cost decoy: we deliberately DON'T call
 * strlen, we reimplement it, so a worker that just parrots "calls
 * strlen" is wrong.
 */

#include <windows.h>

/**
 * Compute the length of a null-terminated byte string.
 *
 * Walks the input pointer one byte at a time until a zero byte is
 * encountered; returns the distance from start to the first zero.
 * Matches the semantics of standard strlen() but is a fresh
 * reimplementation (does not call into CRT). Behavior on a non-null-
 * terminated buffer is undefined.
 *
 * @param str  pointer to a null-terminated C string
 * @return number of bytes before the terminating zero
 */
__declspec(dllexport)
unsigned int __stdcall compute_str_len(const char *str)
{
    const char *cursor = str;
    while (*cursor != '\0') {
        cursor++;
    }
    return (unsigned int)(cursor - str);
}
