# Diablo Reverse Engineering Research Report

## Research Overview
This document compiles findings from researching Diablo series reverse engineering techniques, primarily focused on information gathered from the UnknownCheats forum.

## Primary Source
**UnknownCheats Diablo Series Forum**: https://www.unknowncheats.me/forum/diablo-series/

## Key Findings

### Diablo 4 Reverse Engineering (Primary Thread)
**Thread**: "Diablo 4 Reversal, Structs and Offsets"
**URL**: https://www.unknowncheats.me/forum/diablo-series/575478-diablo-4-reversal-structs-offsets.html

#### Technical Discoveries

1. **Memory Dump Available**
   - Download ID: 39819 (Diablo IV dump)
   - Contains unencrypted strings
   - File SHA256: 9894fd18b54b7b6b942cca884d8755b7d77e172c0078846f3b494fe7769aaf8a
   - Executable SHA256: dd52b02dbe0ff5167a93b55a241ad12e35d5179838a4fdb015c80ba522e3c8c9

2. **Anti-Cheat Detection Methods**
   - Game has protection against memory remapping
   - Detection occurs approximately 5 minutes into gameplay
   - Uses TLS (Thread Local Storage) extensively
   - Monitors page permissions changes
   - Blizzard maps their own ntdll at runtime

3. **Object Manager Structure**
   ```c
   struct PackedMGRSearch {
       int max;
       uintptr_t* ptr;
   };

   // Usage example:
   uintptr_t* classmgr = *(uintptr_t**)((uintptr_t)base + 0x2ABFBF8);
   uintptr_t* ractors = *(uintptr_t**)((uintptr_t)classmgr + 0xA18);
   
   PackedMGRSearch search = { 0x7FFFF, 0 };
   
   while (((uintptr_t * (*)(uintptr_t*, PackedMGRSearch*))(base + 0x522a00))(ractors, &search)) {
       int id = **(int**)((uintptr_t)search.ptr + 0x518);
       const char* name = ((const char* (*)(int, int))(base + 0xeea270))(1, id);
   }
   ```

4. **Import Address Table (IAT) Analysis**
   - Extensive list of imported functions from multiple DLLs
   - Key libraries include:
     - ADVAPI32 (Windows API functions)
     - KERNEL32 (Core Windows functions)
     - USER32 (User interface functions)
     - WS2_32/WSOCK32 (Network functions)
     - vivoxsdk (Voice chat)
     - bink2w64 (Video codec)

5. **Anti-Analysis Techniques**
   - CRC checks: `F2 48 0F 38 F1`
   - ntdll mapping detection patterns
   - Memory protection monitoring
   - Thread suspension detection avoidance required

6. **Key Memory Patterns**
   - Pattern `48 8d ac 24 90 fe ff` - 13 bytes from start of ntdll map
   - First 1000 bytes of ntdll are not mapped
   - Address 0x4FB120 mentioned as potentially interesting

### Broader Diablo Series Research

#### Thread Topics Discovered:
1. **Diablo 2 Resurrected (D2R)**
   - Packet clientless bot development
   - IAT reconstruction techniques
   - Memory coordinate finding
   - SuperSimpleMH tool availability
   - Ultrawide fix discussions

2. **Diablo 3**
   - Bot development discussions
   - Save editing for PS4 versions
   - Auto-exit at low HP implementations
   - Paragon farming automation

3. **General Techniques**
   - Memory scanning with Cheat Engine
   - Python-based automation
   - AutoHotkey scripting
   - Pixel-based detection methods
   - Process memory analysis
   - Anti-cheat bypass methods

### Tools and Libraries Mentioned

#### Development Tools:
- **Cheat Engine**: Memory scanning and analysis
- **x64dbg**: Debugging and reverse engineering
- **IDA Pro**: Disassembly and analysis (implied)
- **Python + PyMeow**: Memory manipulation
- **AutoHotkey**: Input automation

#### Game-Specific Tools:
- **SuperSimpleMH**: Diablo 2 Resurrected maphack
- **EndGame v1.14d**: Free PVP hack for Diablo 2
- **DivinPk v1.0.4**: PVP hack for Diablo 2 1.14d
- **autod2jsp**: Diablo 2 automation tool

### Reverse Engineering Methodologies

#### Memory Analysis:
1. **Static Analysis**:
   - Binary dumps analysis
   - String analysis for unencrypted data
   - Import table examination
   - Pattern searching

2. **Dynamic Analysis**:
   - Runtime memory scanning
   - Hook placement and monitoring
   - Process injection techniques
   - Anti-cheat evasion methods

3. **Network Analysis**:
   - Packet sniffing and analysis
   - Protocol reverse engineering
   - Client-server communication patterns

#### Anti-Cheat Bypass Techniques:
1. **Memory Protection**:
   - Page permission restoration
   - Memory mapping evasion
   - Thread monitoring avoidance

2. **Code Injection**:
   - DLL injection methods
   - Process hollowing
   - Manual DLL mapping

3. **Detection Avoidance**:
   - Syscall monitoring
   - API hooking detection
   - Timing-based evasion

### Key Contributors and Expertise

#### Notable Forum Members:
- **weareup**: Thread starter, experienced with Diablo 4 analysis
- **jambertobbles**: Junior Forum Moderator, provided initial dump
- **metrix**: Master Contributor, file validation
- **NoEcho**: Detailed anti-cheat analysis and bypass attempts

### Security Analysis

#### Blizzard's Protection Mechanisms:
1. **Memory Protection**:
   - Page permission monitoring
   - Memory remapping detection
   - Delayed punishment system (5-minute delay)

2. **Code Integrity**:
   - CRC checking of critical code sections
   - ntdll mapping for API monitoring
   - Thread analysis for suspicious activity

3. **Behavioral Analysis**:
   - Process interaction monitoring
   - Timing analysis for automation detection
   - Input pattern recognition

### Research Applications for Ghidra

#### Potential Integration Points:
1. **Binary Analysis Enhancement**:
   - Import table analysis automation
   - Pattern recognition for game structures
   - Anti-cheat signature detection

2. **Memory Structure Analysis**:
   - Automatic struct generation from patterns
   - Object manager analysis tools
   - Memory layout visualization

3. **Anti-Analysis Detection**:
   - Identify protection mechanisms
   - Catalog evasion techniques
   - Security research automation

### Recommendations for Further Research

#### High Priority:
1. Analyze the Diablo IV dump for additional structures
2. Study the object manager implementation patterns
3. Research network protocol specifications
4. Document anti-cheat bypass methodologies

#### Medium Priority:
1. Compare techniques across Diablo series versions
2. Analyze other Blizzard games for similar patterns
3. Study packet analysis tools and techniques
4. Research automation detection methods

#### Technical Improvements:
1. Develop Ghidra scripts for Diablo-specific analysis
2. Create automated structure identification tools
3. Build pattern matching for game engines
4. Implement anti-cheat signature detection

## Page 2 Extended Analysis

### Extended IAT Analysis (Page 2)

Page 2 continues the extensive Import Address Table reconstruction with hundreds of additional API calls:

**Key API Categories Discovered:**

- **ADVAPI32 Functions:** CryptGetHashParam, CryptCreateHash, RegCreateKeyExA, RegQueryValueExA, CryptHashData, CryptDestroyHash, CryptImportKey, CryptEncrypt - indicates encryption/registry manipulation
- **KERNEL32 Functions:** Extensive memory management, thread control, file operations, process manipulation
- **USER32 Functions:** Window management, input handling, display control
- **WS2_32/WSOCK32:** Network communication, socket operations
- **ntdll Functions:** Low-level system operations, critical sections, heap management
- **SHELL32:** File operations, executable launching
- **CRYPT32:** Certificate handling, data protection
- **vivoxsdk:** Voice communication integration
- **bink2w64:** Video codec operations
- **HID:** Hardware interface device communication

### Object Manager Implementation Details

**PackedMGRSearch Structure:**

```c
struct PackedMGRSearch {
    int max;
    uintptr_t* ptr;
};
```

**Object Manager Iteration Pattern:**

```c
uintptr_t* classmgr = *(uintptr_t**)((uintptr_t)base + 0x2ABFBF8);
uintptr_t* ractors = *(uintptr_t**)((uintptr_t)classmgr + 0xA18);

PackedMGRSearch search = { 0x7FFFF, 0 };

while (((uintptr_t * (*)(uintptr_t*, PackedMGRSearch*))(base + 0x522a00))(ractors, &search)) {
    int id = **(int**)((uintptr_t)search.ptr + 0x518);
    const char* name = ((const char* (*)(int, int))(base + 0xeea270))(1, id);
}
```

### Advanced Anti-Analysis Techniques Discovered

- **Memory Remapping Detection:** Game detects when ntdll is remapped even with proper page permissions (SEC_NO_CHANGE, PAGE_EXECUTE_READ)
- **Thread Monitoring:** System avoids threads with high suspend counts
- **CRC Pattern:** `F2 48 0F 38 F1` - specific integrity checking sequence
- **NTDLL Mapping:** Custom ntdll mapping with pattern `48 8d ac 24 90 fe ff` - 13 bytes before start of ntdll map
- **5-Minute Detection Delay:** Anti-cheat waits approximately 5 minutes before taking action
- **TLS Monitoring:** Thread Local Storage analysis for suspicious behavior
- **Syscall Monitoring:** Potential monitoring of system calls through custom ntdll mapping

## Conclusion

The UnknownCheats Diablo series forum provides extensive technical information about reverse engineering techniques for the entire Diablo series. The research reveals sophisticated anti-cheat mechanisms employed by Blizzard, various bypass techniques, and comprehensive toolchains used by the reverse engineering community.

Key takeaways:

- Diablo 4 employs advanced memory protection and behavioral analysis
- The community has developed sophisticated tools and techniques
- There's extensive knowledge about memory structures and network protocols
- Anti-cheat evasion requires deep understanding of Windows internals

This research provides valuable insights that can be applied to improving Ghidra's binary analysis capabilities, particularly for game reverse engineering and security research applications.

---
*Research compiled from UnknownCheats.me Diablo Series forum*
*Date: January 2025*
 
 