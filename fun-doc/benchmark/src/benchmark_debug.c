/*
 * benchmark_debug.c - tiny live-debug harness for Benchmark.dll.
 *
 * This EXE intentionally calls a handful of exported benchmark functions in a
 * repeatable loop so Ghidra debugger regression tests have a stable process to
 * launch, interrupt, inspect, and terminate.
 */

#include <windows.h>
#include <stdio.h>

#define D2_STAT_LIST_MAGIC 0x01020304
#define SIMPLE_STAT_LIST_MAGIC 0x54415453

typedef unsigned short (__stdcall *calc_crc16_fn)(const unsigned char *data, unsigned int length);
typedef unsigned int (__stdcall *compute_gcd_fn)(unsigned int a, unsigned int b);
typedef int (__stdcall *get_stat_list_flags_fn)(int *pStatList);
typedef unsigned int (__stdcall *get_stat_list_layer_fn)(const unsigned char *pStatList);
typedef int (__stdcall *get_stat_list_owner_guid_fn)(int *pStatList);
typedef int (__stdcall *get_stat_list_prev_link_fn)(int *pStatList);
typedef int (__stdcall *advance_parser_state_fn)(int current_state, unsigned char input);
typedef unsigned int (__stdcall *compute_str_len_fn)(const char *str);

struct StatEntry {
    unsigned short stat_id;
    unsigned short flags;
    int value;
};

struct StatList {
    unsigned int magic;
    unsigned int list_flags;
    unsigned int entry_count;
    struct StatEntry entries[16];
};

typedef int (__stdcall *stat_list_add_fn)(
    struct StatList *list,
    unsigned short id,
    unsigned short flags,
    int value);

static volatile LONG g_debug_heartbeat = 0;
static volatile DWORD g_debug_last_result = 0;

static FARPROC require_export(HMODULE module, const char *name)
{
    FARPROC proc = GetProcAddress(module, name);
    if (proc == NULL) {
        fprintf(stderr, "missing export: %s\n", name);
        ExitProcess(2);
    }
    return proc;
}

static void build_sibling_path(char *buffer, DWORD buffer_size, const char *file_name)
{
    DWORD length = GetModuleFileNameA(NULL, buffer, buffer_size);
    char *cursor;

    if (length == 0 || length >= buffer_size) {
        fprintf(stderr, "GetModuleFileNameA failed\n");
        ExitProcess(2);
    }

    cursor = buffer + length;
    while (cursor > buffer && cursor[-1] != '\\' && cursor[-1] != '/') {
        cursor--;
    }
    lstrcpynA(cursor, file_name, (int)(buffer_size - (cursor - buffer)));
}

int main(int argc, char **argv)
{
    char dll_path[MAX_PATH];
    HMODULE benchmark;
    calc_crc16_fn calc_crc16;
    compute_gcd_fn compute_gcd;
    get_stat_list_flags_fn get_stat_list_flags;
    get_stat_list_layer_fn get_stat_list_layer;
    get_stat_list_owner_guid_fn get_stat_list_owner_guid;
    get_stat_list_prev_link_fn get_stat_list_prev_link;
    advance_parser_state_fn advance_parser_state;
    compute_str_len_fn compute_str_len;
    stat_list_add_fn stat_list_add;
    DWORD runtime_ms = 300000;
    DWORD started = GetTickCount();
    unsigned char payload[] = { 'D', '2', 'M', 'C', 'P', 0x13, 0x37 };
    int d2_stat_list[16] = { 0 };
    struct StatList simple_list;
    int parser_state = 0;

    if (argc >= 3 && lstrcmpiA(argv[1], "--seconds") == 0) {
        runtime_ms = (DWORD)(strtoul(argv[2], NULL, 10) * 1000);
    }

    d2_stat_list[0] = D2_STAT_LIST_MAGIC;
    d2_stat_list[1] = 7;
    d2_stat_list[4] = 0x20;
    d2_stat_list[8] = 0x12345678;
    d2_stat_list[13] = 0x00ABCDEF;

    ZeroMemory(&simple_list, sizeof(simple_list));
    simple_list.magic = SIMPLE_STAT_LIST_MAGIC;
    simple_list.list_flags = 0x400;

    build_sibling_path(dll_path, sizeof(dll_path), "Benchmark.dll");
    benchmark = LoadLibraryA(dll_path);
    if (benchmark == NULL) {
        fprintf(stderr, "LoadLibraryA failed for %s (error=%lu)\n", dll_path, GetLastError());
        return 2;
    }

    calc_crc16 = (calc_crc16_fn)require_export(benchmark, "calc_crc16");
    compute_gcd = (compute_gcd_fn)require_export(benchmark, "compute_gcd");
    get_stat_list_flags = (get_stat_list_flags_fn)require_export(benchmark, "get_stat_list_flags");
    get_stat_list_layer = (get_stat_list_layer_fn)require_export(benchmark, "get_stat_list_layer");
    get_stat_list_owner_guid =
        (get_stat_list_owner_guid_fn)require_export(benchmark, "get_stat_list_owner_guid");
    get_stat_list_prev_link =
        (get_stat_list_prev_link_fn)require_export(benchmark, "get_stat_list_prev_link");
    advance_parser_state = (advance_parser_state_fn)require_export(benchmark, "advance_parser_state");
    compute_str_len = (compute_str_len_fn)require_export(benchmark, "compute_str_len");
    stat_list_add = (stat_list_add_fn)require_export(benchmark, "stat_list_add");

    printf("BenchmarkDebug.exe pid=%lu dll=%s\n", GetCurrentProcessId(), dll_path);
    fflush(stdout);

    while (GetTickCount() - started < runtime_ms) {
        DWORD result = 0;
        LONG heartbeat = InterlockedIncrement(&g_debug_heartbeat);

        result += calc_crc16(payload, sizeof(payload));
        result += compute_gcd(heartbeat + 144, 84);
        result += get_stat_list_flags(d2_stat_list);
        result += get_stat_list_layer((const unsigned char *)d2_stat_list);
        result += get_stat_list_owner_guid(d2_stat_list);
        result += get_stat_list_prev_link(d2_stat_list);
        parser_state = advance_parser_state(parser_state, (unsigned char)('a' + (heartbeat % 26)));
        result += (DWORD)parser_state;
        result += compute_str_len("diablo2 benchmark debugger harness");
        result += stat_list_add(&simple_list, (unsigned short)(heartbeat & 0xffff), 1, result);

        g_debug_last_result = result;
        Sleep(100);
    }

    FreeLibrary(benchmark);
    return (int)(g_debug_last_result & 0xff);
}
