/*
 * gcd.c — Archetype: recursion.
 *
 * Euclidean algorithm for greatest common divisor. Classic recursive
 * pattern — the function calls itself with rearranged arguments,
 * returning the base case when the second argument hits zero. Tests
 * whether fun-doc recognizes recursion, names the inputs meaningfully,
 * and identifies the algorithm in the plate.
 */

#include <windows.h>

/**
 * Compute the greatest common divisor via Euclid's algorithm.
 *
 * Recursive implementation: gcd(a, b) = gcd(b, a mod b), with
 * gcd(a, 0) = a. Handles the classical GCD definition for
 * non-negative integers. No overflow protection — assumes inputs
 * are within a reasonable range.
 *
 * @param a  first input
 * @param b  second input
 * @return the greatest common divisor of a and b
 */
__declspec(dllexport)
unsigned int __stdcall compute_gcd(unsigned int a, unsigned int b)
{
    unsigned int remainder;

    if (b == 0) {
        return a;
    }
    remainder = a % b;
    return compute_gcd(b, remainder);
}
