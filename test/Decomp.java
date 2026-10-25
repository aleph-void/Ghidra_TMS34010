// Disassemble and create functions at the given addresses, analyse, and write the
// decompiled C of each. Script args: <out> <hex address>...
//@category Testing
import java.io.PrintStream;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
public class Decomp extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] a = getScriptArgs();
		for (int i = 1; i < a.length; i++) {
			disassemble(toAddr(Long.decode(a[i])));
			createFunction(toAddr(Long.decode(a[i])), null);
		}
		analyzeAll(currentProgram);
		DecompInterface di = new DecompInterface();
		di.openProgram(currentProgram);
		PrintStream out = new PrintStream(a[0]);
		for (int i = 1; i < a.length; i++) {
			Function f = getFunctionAt(toAddr(Long.decode(a[i])));
			DecompileResults r = di.decompileFunction(f, 60, monitor);
			out.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : r.getErrorMessage());
		}
		di.dispose();
		out.close();
	}
}
