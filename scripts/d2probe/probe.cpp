// Headless-viability probe for running D2 in a container.
//
// Answers, with HRESULTs rather than opinions, the two things standing between
// the current setup and a headless Windows container:
//
//   1. Can DirectSound create and play a secondary buffer with no audio
//      endpoint? The whole audio-capture stack hooks buffer Lock/Unlock, so if
//      buffers cannot be created there is nothing to capture and remote-play
//      audio is dead in the water.
//   2. Does the GDI render path survive with no interactive desktop?
//      CreateWindow + CreateDIBSection + StretchBlt is exactly how D2Gdi.dll
//      presents (measured: 25/sec, 8bpp palettised), so this reproduces the
//      real path rather than approximating it.
//
// Built 32-bit to match Game.exe. Writes to a log file as well as stdout,
// because in Session 0 there is no console to read.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
// dsound.h needs WAVEFORMATEX, which WIN32_LEAN_AND_MEAN strips out from under
// it -- include the multimedia headers first or dsound.h fails to parse.
#include <mmreg.h>
#include <mmsystem.h>
#include <dsound.h>
#include <stdio.h>

static FILE* g_log = nullptr;

static void L(const char* fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    fputs(buf, stdout);
    fputs("\n", stdout);
    if (g_log) { fputs(buf, g_log); fputs("\n", g_log); fflush(g_log); }
}

static BOOL CALLBACK EnumCb(LPGUID, LPCSTR desc, LPCSTR, LPVOID ctx)
{
    L("    device: %s", desc ? desc : "(null)");
    (*(int*)ctx)++;
    return TRUE;
}

int main()
{
    fopen_s(&g_log, "C:\\tmp\\d2probe\\probe_result.txt", "w");

    // ---- context -----------------------------------------------------------
    DWORD sess = 0xFFFFFFFF;
    ProcessIdToSessionId(GetCurrentProcessId(), &sess);
    char user[256] = ""; DWORD ulen = sizeof(user);
    GetUserNameA(user, &ulen);
    char winsta[256] = "(none)";
    HWINSTA ws = GetProcessWindowStation();
    if (ws) GetUserObjectInformationA(ws, UOI_NAME, winsta, sizeof(winsta), nullptr);
    char desk[256] = "(none)";
    HDESK dk = GetThreadDesktop(GetCurrentThreadId());
    if (dk) GetUserObjectInformationA(dk, UOI_NAME, desk, sizeof(desk), nullptr);
    L("== CONTEXT ==");
    L("  session      : %lu%s", sess, sess == 0 ? "   <-- Session 0 (container-like)" : "");
    L("  user         : %s", user);
    L("  windowstation: %s", winsta);
    L("  desktop      : %s", desk);

    // ---- 2. the GDI render path -------------------------------------------
    // Done first: DirectSound wants an HWND for SetCooperativeLevel.
    L("== GDI RENDER PATH ==");
    WNDCLASSA wc = {};
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandleA(nullptr);
    wc.lpszClassName = "D2ProbeWnd";
    ATOM a = RegisterClassA(&wc);
    L("  RegisterClass    : %s (err %lu)", a ? "OK" : "FAIL", a ? 0 : GetLastError());
    HWND hwnd = CreateWindowExA(0, "D2ProbeWnd", "probe", WS_OVERLAPPEDWINDOW,
                                0, 0, 800, 600, nullptr, nullptr, wc.hInstance, nullptr);
    L("  CreateWindowEx   : %s (err %lu)", hwnd ? "OK" : "FAIL", hwnd ? 0 : GetLastError());

    // 8bpp palettised DIB + StretchBlt -- byte for byte what D2Gdi.dll does.
    HDC dc = hwnd ? GetDC(hwnd) : nullptr;
    L("  GetDC            : %s", dc ? "OK" : "FAIL");
    struct { BITMAPINFOHEADER h; RGBQUAD pal[256]; } bi = {};
    bi.h.biSize = sizeof(BITMAPINFOHEADER);
    bi.h.biWidth = 800; bi.h.biHeight = -600;      // top-down, as D2 does
    bi.h.biPlanes = 1; bi.h.biBitCount = 8; bi.h.biCompression = BI_RGB;
    bi.h.biClrUsed = 256;
    for (int i = 0; i < 256; ++i)
    { bi.pal[i].rgbRed = (BYTE)i; bi.pal[i].rgbGreen = (BYTE)i; bi.pal[i].rgbBlue = (BYTE)i; }
    void* bits = nullptr;
    HDC memdc = dc ? CreateCompatibleDC(dc) : nullptr;
    HBITMAP dib = memdc ? CreateDIBSection(memdc, (BITMAPINFO*)&bi, DIB_RGB_COLORS,
                                           &bits, nullptr, 0) : nullptr;
    L("  CreateDIBSection : %s (err %lu)  bits=%p",
      dib ? "OK" : "FAIL", dib ? 0 : GetLastError(), bits);
    int blt = 0;
    if (dib && memdc && dc)
    {
        HGDIOBJ old = SelectObject(memdc, dib);
        if (bits) memset(bits, 0x40, 800 * 600);
        blt = StretchBlt(dc, 0, 0, 800, 600, memdc, 0, 0, 800, 600, SRCCOPY);
        L("  StretchBlt       : %s (err %lu)", blt ? "OK" : "FAIL", blt ? 0 : GetLastError());
        SelectObject(memdc, old);
    }

    // ---- 1. DirectSound ----------------------------------------------------
    L("== DIRECTSOUND ==");
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    L("  CoInitializeEx   : 0x%08lX", hr);

    int ndev = 0;
    hr = DirectSoundEnumerateA(EnumCb, &ndev);
    L("  Enumerate        : 0x%08lX  devices=%d", hr, ndev);

    LPDIRECTSOUND8 ds = nullptr;
    hr = DirectSoundCreate8(nullptr, &ds, nullptr);
    L("  DirectSoundCreate8: 0x%08lX %s", hr,
      hr == DSERR_NODRIVER ? "(DSERR_NODRIVER - no audio device)" :
      SUCCEEDED(hr) ? "OK" : "");

    if (SUCCEEDED(hr) && ds)
    {
        // DSSCL_NORMAL against the desktop window if we have no window of our
        // own -- SetCooperativeLevel refuses a null HWND.
        HWND coop = hwnd ? hwnd : GetDesktopWindow();
        hr = ds->SetCooperativeLevel(coop, DSSCL_NORMAL);
        L("  SetCoopLevel     : 0x%08lX", hr);

        WAVEFORMATEX wf = {};
        wf.wFormatTag = WAVE_FORMAT_PCM;
        wf.nChannels = 2; wf.nSamplesPerSec = 22050; wf.wBitsPerSample = 16;
        wf.nBlockAlign = 4; wf.nAvgBytesPerSec = 22050 * 4;
        DSBUFFERDESC bd = {};
        bd.dwSize = sizeof(bd);
        // GLOBALFOCUS is what the capture stack needs so buffers keep sounding
        // when the window is not foreground.
        bd.dwFlags = DSBCAPS_CTRLVOLUME | DSBCAPS_CTRLPAN | DSBCAPS_GETCURRENTPOSITION2
                   | DSBCAPS_GLOBALFOCUS;
        bd.dwBufferBytes = 22050 * 4;
        bd.lpwfxFormat = &wf;

        LPDIRECTSOUNDBUFFER buf = nullptr;
        hr = ds->CreateSoundBuffer(&bd, &buf, nullptr);
        L("  CreateSoundBuffer: 0x%08lX %s", hr, SUCCEEDED(hr) ? "OK" : "FAIL");

        if (SUCCEEDED(hr) && buf)
        {
            void* p1 = nullptr; DWORD b1 = 0; void* p2 = nullptr; DWORD b2 = 0;
            hr = buf->Lock(0, 0, &p1, &b1, &p2, &b2, DSBLOCK_ENTIREBUFFER);
            L("  Lock             : 0x%08lX  bytes=%lu", hr, b1);
            if (SUCCEEDED(hr))
            {
                if (p1) memset(p1, 0, b1);          // silence, not noise
                buf->Unlock(p1, b1, p2, b2);
                L("  Unlock           : OK");
            }
            hr = buf->Play(0, 0, 0);
            L("  Play             : 0x%08lX %s", hr, SUCCEEDED(hr) ? "OK" : "FAIL");
            Sleep(120);
            DWORD play = 0, write = 0;
            hr = buf->GetCurrentPosition(&play, &write);
            L("  GetCurrentPos    : 0x%08lX  play=%lu write=%lu %s", hr, play, write,
              (SUCCEEDED(hr) && play > 0) ? "<-- CURSOR ADVANCING" : "<-- cursor stuck");
            buf->Stop();
            buf->Release();
        }
        ds->Release();
    }

    L("== VERDICT ==");
    L("  GDI path usable  : %s", (hwnd && dib && blt) ? "YES" : "NO");
    L("  DirectSound usable: (see CreateSoundBuffer / GetCurrentPos above)");

    if (dib) DeleteObject(dib);
    if (memdc) DeleteDC(memdc);
    if (dc && hwnd) ReleaseDC(hwnd, dc);
    if (hwnd) DestroyWindow(hwnd);
    CoUninitialize();
    if (g_log) fclose(g_log);
    return 0;
}
