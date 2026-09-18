// Dump the analysis facts the regression baseline asserts, so the baseline can
// be derived from a real Ghidra analysis instead of guessed at.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryBlock;

public class DumpBenchmarkFacts extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== PROGRAM ===");
        println("name=" + currentProgram.getName());
        println("language=" + currentProgram.getLanguageID());
        println("compiler=" + currentProgram.getCompilerSpec().getCompilerSpecID());
        println("processor=" + currentProgram.getLanguage().getProcessor());
        println("imageBase=" + currentProgram.getImageBase());
        println("functionCount=" + currentProgram.getFunctionManager().getFunctionCount());
        println("symbolCount=" + currentProgram.getSymbolTable().getNumSymbols());

        println("=== BLOCKS ===");
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            println("block=" + b.getName() + " start=" + b.getStart() + " size=" + b.getSize());
        }

        println("=== STRINGS ===");
        int strings = 0;
        DataIterator di = currentProgram.getListing().getDefinedData(true);
        while (di.hasNext()) {
            Data d = di.next();
            if (d.getValue() instanceof String) {
                strings++;
            }
        }
        println("definedStringCount=" + strings);

        println("=== FUNCTIONS ===");
        BasicBlockModel bbm = new BasicBlockModel(currentProgram);
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
        while (fi.hasNext()) {
            Function f = fi.next();
            int blocks = 0;
            CodeBlockIterator cbi = bbm.getCodeBlocksContaining(f.getBody(), monitor);
            while (cbi.hasNext()) { cbi.next(); blocks++; }
            int instructions = 0;
            InstructionIterator ii = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (ii.hasNext()) { ii.next(); instructions++; }
            int xrefs = 0;
            for (Reference r : getReferencesTo(f.getEntryPoint())) { xrefs++; }
            StringBuilder sb = new StringBuilder();
            sb.append("fn name=").append(f.getName())
              .append(" entry=").append(f.getEntryPoint())
              .append(" params=").append(f.getParameterCount())
              .append(" blocks=").append(blocks)
              .append(" instructions=").append(instructions)
              .append(" xrefsTo=").append(xrefs)
              .append(" thunk=").append(f.isThunk())
              .append(" sig=").append(f.getSignature().getPrototypeString());
            println(sb.toString());

            DecompileResults res = decomp.decompileFunction(f, 45, monitor);
            if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                String c = res.getDecompiledFunction().getC();
                println("  decompiled_chars=" + c.length());
                if (f.getName().equals("calc_crc16") || f.getName().equals("compute_gcd")
                        || f.getName().equals("advance_parser_state")) {
                    for (String line : c.split("\n")) {
                        println("  | " + line);
                    }
                }
            } else {
                println("  DECOMPILE FAILED");
            }
        }
        decomp.dispose();
        println("=== END ===");
    }
}
