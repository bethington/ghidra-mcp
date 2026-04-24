/*
 * stat_list_add.c — Archetype: struct-pointer mutator.
 *
 * Exercises whether fun-doc can identify a struct type, name the
 * fields, and write a plate that describes the mutation. The struct
 * mirrors the D2 StatList pattern (magic number + flags + a count
 * + a bounded array of stats) but is simplified for the benchmark.
 * The function appends one stat entry to the list, bumping the
 * count and rejecting on overflow. Realistic struct-access work.
 */

#include <windows.h>

#define STAT_LIST_MAGIC      0x54415453  /* 'STAT' */
#define STAT_LIST_CAPACITY   16

struct StatEntry {
    unsigned short stat_id;
    unsigned short flags;
    int value;
};

struct StatList {
    unsigned int magic;
    unsigned int list_flags;
    unsigned int entry_count;
    struct StatEntry entries[STAT_LIST_CAPACITY];
};

/**
 * Append one stat entry to a StatList.
 *
 * Validates the list's magic number (rejects corrupted or
 * uninitialized lists). If the list has room (entry_count <
 * STAT_LIST_CAPACITY), writes the new entry at the next free slot,
 * increments entry_count, and returns 1. Returns 0 on overflow or
 * corruption. The list's list_flags OR'd-in bits are untouched.
 *
 * @param list   pointer to the StatList to mutate
 * @param id     stat id (u16, e.g. enum StatType)
 * @param flags  entry flags (u16)
 * @param value  stat numeric value
 * @return 1 on success, 0 on overflow / corruption
 */
__declspec(dllexport)
int __stdcall stat_list_add(struct StatList *list, unsigned short id, unsigned short flags, int value)
{
    unsigned int slot_index;
    struct StatEntry *slot;

    if (list == NULL) {
        return 0;
    }
    if (list->magic != STAT_LIST_MAGIC) {
        return 0;
    }
    if (list->entry_count >= STAT_LIST_CAPACITY) {
        return 0;
    }

    slot_index = list->entry_count;
    slot = &list->entries[slot_index];
    slot->stat_id = id;
    slot->flags = flags;
    slot->value = value;

    list->entry_count = slot_index + 1;
    return 1;
}
