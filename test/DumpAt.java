// Decode the instruction at each address listed in a file (one hex Ghidra address per line) with
// Language.parse (no flow). Prints "<address-hex> <length> <instruction text | BAD (...)>".
// Script args: <address list> <outfile>
//@category Testing

import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.ProcessorContextImpl;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;

public class DumpAt extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		PrintStream out = new PrintStream(args[1]);
		Language lang = currentProgram.getLanguage();
		for (String line : Files.readAllLines(Path.of(args[0]))) {
			line = line.trim();
			if (line.isEmpty()) continue;
			Address a = toAddr(Long.parseUnsignedLong(line, 16));
			String text;
			int len = 0;
			try {
				ProcessorContextImpl ctx = new ProcessorContextImpl(lang);
				MemBuffer buf = new DumbMemBufferImpl(currentProgram.getMemory(), a);
				InstructionPrototype proto = lang.parse(buf, ctx, false);
				PseudoInstruction ins = new PseudoInstruction(currentProgram, a, proto, buf, ctx);
				text = ins.toString();
				len = ins.getLength();
			}
			catch (Exception e) {
				text = "BAD (" + String.valueOf(e.getMessage()).split("\n")[0] + ")";
			}
			out.printf("%08x %d %s%n", a.getOffset(), len, text);
		}
		out.close();
	}
}
