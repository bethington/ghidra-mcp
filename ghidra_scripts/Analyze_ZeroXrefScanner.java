// Zero Xref Scanner
//
// Scans the current program for functions with zero cross-references and reports their names and sizes. Useful for identifying dead code or unreferenced utility functions.
//
// Usage: Run from Script Manager on any program.
// Output: Console listing of all zero-xref functions with sizes.
//
// @author Ben Ethington
// @category Diablo 2.Analysis
// @description Scan current program for zero-xref functions
// @menupath Diablo 2.Analysis.Zero Xref Scanner

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class Analyze_ZeroXrefScanner extends GhidraScript {
    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();
        
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
        
        println("PROGRAM: " + currentProgram.getName() + " (" + currentProgram.getDomainFile().getPathname() + ")");
        println("TOTAL_FUNCTIONS: " + totalFuncs);
        println("ZERO_XREF_FUNCTIONS: " + zeroXrefCount);
        println("TOP_50_BY_SIZE:");
        
        int count = 0;
        for (String r : results) {
            if (count >= 50) break;
            int p1 = r.indexOf('|');
            int p2 = r.indexOf('|', p1 + 1);
            String sz = r.substring(0, p1);
            String addr = r.substring(p1 + 1, p2);
            String name = r.substring(p2 + 1);
            println("  " + sz + " bytes | " + addr + " | " + name);
            count++;
        }
        
        int gt1000 = 0, gt500 = 0, gt200 = 0, gt100 = 0, gt50 = 0, lt50 = 0;
        long totalBytes = 0;
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
        println("SIZE_DISTRIBUTION:");
        println("  >1000 bytes: " + gt1000);
        println("  501-1000:    " + gt500);
        println("  201-500:     " + gt200);
        println("  101-200:     " + gt100);
        println("  51-100:      " + gt50);
        println("  <=50:        " + lt50);
        println("TOTAL_RECLAIMABLE_BYTES: " + totalBytes);
    }
}
