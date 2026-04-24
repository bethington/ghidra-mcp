# NOTICE — Third-party software posture for this directory

This directory is a local-machine staging area for **Microsoft Visual C++ 6.0 Service Pack 6** binaries used to build the fun-doc benchmark binary. The binaries themselves are NOT committed to this repository; see `.gitignore`. This NOTICE.md documents the authorship, the legal posture, and what authors of this repository claim and do not claim.

## What is stored here when fully populated

After running `bootstrap_vc6.py`, the following third-party files land under `VC98/`:

| Files | Copyright holder | Source |
| --- | --- | --- |
| `VC98/Bin/cl.exe`, `link.exe`, `C1.DLL`, `C1XX.DLL`, `CVTRES.EXE`, `NMAKE.EXE`, others | Microsoft Corporation | Visual Studio 6.0 Enterprise CD1 ISO + Service Pack 6 self-extractor |
| `VC98/Bin/C2.DLL` | Microsoft Corporation | Visual C++ 6.0 Processor Pack (`vcpp5.exe`) |
| `VC98/Bin/MSPDB60.DLL`, `MSDIS110.DLL`, `MSOBJ10.DLL` | Microsoft Corporation | Visual Studio 6.0 Enterprise CD1 ISO |
| `VC98/Include/*.h` | Microsoft Corporation | Visual Studio 6.0 Enterprise CD1 ISO + SP6 |
| `VC98/Lib/*.lib` | Microsoft Corporation | Visual Studio 6.0 Enterprise CD1 ISO + SP6 |
| `VS7/Bin/link.exe`, `cvtres.exe`, `mspdb71.dll`, `msdis140.dll`, `msvcr71.dll` | Microsoft Corporation | Visual Studio .NET 2003 Professional CD1 ISO (optional — staged by `bootstrap_vc6.py --vs7-source`; used for the mixed toolchain that matches D2 1.13d's `OptionalHeader.LinkerVersion` of 7.10) |

Copyright in these files runs through approximately **2093** (1998 + 95 years under 17 U.S.C. § 302(c) for works-for-hire). They are not public domain and Microsoft has not declared them freely redistributable.

## What this project claims

- The authors of this repository ("the project") have NOT received a license from Microsoft Corporation to redistribute these files.
- The project does NOT redistribute these files. The `.gitignore` in this directory excludes every file except this NOTICE, `README.md`, and `.gitignore` itself. `bootstrap_vc6.py` operates on source media that the END USER is expected to own and license.
- Every user who runs `bootstrap_vc6.py` is individually responsible for holding a valid license to Visual Studio 6.0 (Enterprise, Professional, or Standard) and for compliance with its End User License Agreement.

## What this project does NOT claim

The project does **NOT** claim any of the following — if you see any of these claims elsewhere in the repository or in discussions of it, they are incorrect and should be corrected:

- This project is distributed under **17 U.S.C. § 108** (library/archives exemption). False — § 108 applies only to qualifying libraries and archives; this project is neither. Even for qualifying entities, § 108(c) prohibits making preservation copies available outside the library's premises.
- This project is distributed under the **DMCA § 1201 preservation exemption**. False — the § 1201 exemption authorizes qualifying institutions to circumvent technical protection measures for preservation; it does not authorize redistribution, and it does not apply to non-institutional actors. The most recent (2024) triennial rulemaking did not expand either limit.
- Visual Studio 6.0 is **"abandonware"** and therefore freely distributable. False — U.S. copyright law has no abandonment doctrine analogous to trademark. Non-sale, discontinuation, and end of vendor support do not forfeit copyright.
- Microsoft has **authorized** redistribution of these binaries. False — no such public authorization exists for VC6 binaries. Microsoft's non-enforcement against specific public copies (e.g., certain Internet Archive items) is tolerance, not license.
- **"Fair use"** covers archival redistribution of commercial software. Overstated — fair use is a case-by-case defense, not a license grant, and no appellate case supports wholesale redistribution of a complete commercial software product for "preservation." The cases often cited (Sega v. Accolade, Sony v. Connectix) protected *reverse engineering for interoperability*, not redistribution.

## Why we chose this posture

Three reasons:

1. **Legal honesty**: the legal theories that are sometimes invoked for "archival" redistribution (§ 108, § 1201, fair use, abandonware) do not actually protect a public GitHub repository redistributing Microsoft binaries. Claiming they do would be overclaiming; pretending the question doesn't exist would be worse.
2. **License responsibility stays with the user**: contributors who want to build this project bring their own VC6 license and source media. The project does not shift that responsibility to itself through a "we already provided the binaries" convenience.
3. **Enforcement reality**: empirically Microsoft rarely pursues legacy dev-tool redistribution on GitHub, but DMCA takedowns against other legacy Microsoft products on GitHub have happened (2020, 2022 notices on record at github/dmca). The safe posture is to not be in that population at all.

## Trademarks

"Microsoft", "Visual Studio", and "Visual C++" are trademarks or registered trademarks of Microsoft Corporation. Use of these names in this repository is descriptive (identifying the product that produced the binaries) and does not imply endorsement or affiliation.

## Takedown / contact

If Microsoft Corporation or another rights-holder believes this repository is in error despite the above, please open an issue on the repository or contact the maintainer listed in `CODEOWNERS` / the project's root `README.md`. The maintainer commits to removing any disputed content within one business day of a good-faith report and to discussing the factual basis.

## Source references

Legal claims above are grounded in the following:

- [17 U.S.C. § 108 — Reproduction by libraries and archives](https://www.law.cornell.edu/uscode/text/17/108)
- [17 U.S.C. § 302(c) — Copyright duration for works-for-hire](https://www.law.cornell.edu/uscode/text/17/302)
- [U.S. Copyright Office — Section 1201 Ninth Triennial Rulemaking (2024)](https://www.copyright.gov/1201/2024/)
- [Sega Enterprises v. Accolade, 977 F.2d 1510 (9th Cir. 1992)](https://law.justia.com/cases/federal/appellate-courts/F2/977/1510/)
- [Sony Computer Entertainment v. Connectix, 203 F.3d 596 (9th Cir. 2000)](https://law.justia.com/cases/federal/appellate-courts/F3/203/596/)
- [Vault Corp. v. Quaid Software, 847 F.2d 255 (5th Cir. 1988)](https://law.justia.com/cases/federal/appellate-courts/F2/847/255/)
- [ARL — Code of Best Practices in Fair Use for Software Preservation](https://www.arl.org/code-fair-use-software-preservation/)
