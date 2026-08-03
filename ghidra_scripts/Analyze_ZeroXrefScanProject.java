// Zero Xref Scan Project
//
// Scans multiple binaries in the project for functions with zero cross-references. Reports total byte size of unreferenced code per binary for dead code analysis.
//
// Usage: Args: [0]=optional target path. Defaults to hardcoded 1.13c binaries.
// Output: Console report of zero-xref function counts and sizes per binary.
//
// @author Ben Ethington
// @category Diablo 2.Analysis
// @description Scan project binaries for zero-xref functions
// @menupath Diablo 2.Analysis.Zero Xref Scan Project

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.model.*;
import java.util.*;

public class Analyze_ZeroXrefScanProject extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String targetPath = (args != null && args.length > 0) ? args[0] : null;
        
        Project project = state.getProject();
        ProjectData projectData = project.getProjectData();
        
        String[] vanillaPaths = {
            "/Vanilla/1.13c/D2Client.dll",
            "/Vanilla/1.13c/D2Common.dll",
            "/Vanilla/1.13c/D2Game.dll",
            "/Vanilla/1.13c/D2Win.dll",
            "/Vanilla/1.13c/D2Gfx.dll",
            "/Vanilla/1.13c/D2DDraw.dll",
            "/Vanilla/1.13c/Storm.dll",
            "/Vanilla/1.13c/Fog.dll"
        };
        
        long grandTotalBytes = 0;
        int grandTotalZeroXref = 0;
        
        for (String vpath : vanillaPaths) {
            if (targetPath != null && !vpath.equals(targetPath)) continue;
            
            DomainFile df = projectData.getFile(vpath);
            if (df == null) {
                println("NOT FOUND: " + vpath);
                continue;
            }
            
            DomainObject obj = df.getDomainObject(this, true, false, monitor);
            if (!(obj instanceof Program)) {
                println("NOT A PROGRAM: " + vpath);
                if (obj != null) obj.release(this);
                continue;
            }
            
            Program prog = (Program) obj;
            try {
                scanProgram(prog, vpath);
            } finally {
                prog.release(this);
            }
        }
    }
    
    private void scanProgram(Program prog, String path) {
        FunctionManager fm = prog.getFunctionManager();
        ReferenceManager rm = prog.getReferenceManager();
        
        List<String> results = new ArrayList<>();
        int totalFuncs = 0;
        int zeroXrefCount = 0;
        
        FunctionIterator iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            Function f = iter.next();
            totalFuncs++;
            
            ReferenceIterator refs = rm.getReferencesTo(f.getEntryPoint());
            int refCount = 0;
            while (refs.hasNext()) {
                refs.next();
                refCount++;
            }
            
            if (refCount == 0) {
                zeroXrefCount++;
                long bodySize = f.getBody().getNumAddresses();
                String name = f.getName();
                String addr = f.getEntryPoint().toString();
                results.add(bodySize + "|" + addr + "|" + name);
            }
        }
        
        results.sort(new Comparator<String>() {
            public int compare(String a, String b) {
                long sizeA = Long.parseLong(a.substring(0, a.indexOf('|')));
                long sizeB = Long.parseLong(b.substring(0, b.indexOf('|')));
                return Long.compare(sizeB, sizeA);
            }
        });
        
        long totalBytes = 0;
        int gt1000 = 0, gt500 = 0, gt200 = 0, gt100 = 0, gt50 = 0, lt50 = 0;
        for (String r : results) {
            long sz = Long.parseLong(r.substring(0, r.indexOf('|')));
            totalBytes += sz;
            if (sz > 1000) gt1000++;
            else if (sz > 500) gt500++;
            else if (sz > 200) gt200++;
            else if (sz > 100) gt100++;
            else if (sz > 50) gt50++;
            else lt50++;
        }
        
        println("========================================");
        println("DLL: " + prog.getName() + " (" + path + ")");
        println("  Total functions: " + totalFuncs);
        println("  Zero-xref: " + zeroXrefCount);
        println("  Reclaimable bytes: " + totalBytes);
        println("  Dist: >1K=" + gt1000 + " 501-1K=" + gt500 + " 201-500=" + gt200 + " 101-200=" + gt100 + " 51-100=" + gt50 + " <=50=" + lt50);
        println("  TOP 25:");
        
        int count = 0;
        for (String r : results) {
            if (count >= 25) break;
            int p1 = r.indexOf('|');
            int p2 = r.indexOf('|', p1 + 1);
            println("    " + r.substring(0, p1) + " bytes | " + r.substring(p1+1, p2) + " | " + r.substring(p2+1));
            count++;
        }
    }
}
