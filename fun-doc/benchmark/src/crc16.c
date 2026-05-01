/*
 * crc16.c — fun-doc benchmark walking-skeleton function.
 *
 * This file is authored from scratch (not reconstructed from a specific D2
 * bytecode pattern) to prove the benchmark pipeline end-to-end before we
 * invest in D2-derived function authoring. Later tiers will replace / join
 * this with reconstructions of real D2 functions. Keep this file tiny —
 * its only job is to exercise the build / ground-truth / reset / score
 * path.
 */

#include <windows.h>

/**
 * Compute CRC-16-CCITT checksum over a byte buffer.
 *
 * Uses polynomial 0x1021 (CCITT / XMODEM variant), initial value 0xFFFF,
 * no input reflection, no output reflection, no final XOR. Processes
 * one byte at a time, shifting through 8 bits of state per byte. This is
 * the classic CRC-16 used in a lot of network and storage protocols.
 *
 * @param data   pointer to the input buffer
 * @param length number of bytes to checksum
 * @return the 16-bit CRC
 */
__declspec(dllexport)
unsigned short __stdcall calc_crc16(const unsigned char *data, unsigned int length)
{
    unsigned short crc = 0xFFFF;
    unsigned int byte_index;
    unsigned int bit_index;

    for (byte_index = 0; byte_index < length; byte_index++) {
        crc ^= (unsigned short)(data[byte_index] << 8);
        for (bit_index = 0; bit_index < 8; bit_index++) {
            if (crc & 0x8000) {
                crc = (unsigned short)((crc << 1) ^ 0x1021);
            } else {
                crc = (unsigned short)(crc << 1);
            }
        }
    }
    return crc;
}
