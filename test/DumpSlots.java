// Decode the instruction at the start of every fixed-size slot of each initialized memory block
// (Language.parse, no flow), for differential testing against MAME's disassembler.
// Prints one line per slot: "<offset-hex> <length> <instruction text | BAD (...)>"
// Script args: <outfile> <slot size in bytes> [constructors-out]
//   constructors-out: every SLEIGH constructor (file:line) used by some decoded slot
//@category Testing

import java.io.PrintStream;

import java.util.TreeSet;

import ghidra.app.plugin.processors.sleigh.ConstructState;
import ghidra.app.plugin.processors.sleigh.SleighInstructionPrototype;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.ProcessorContextImpl;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryBlock;

public class DumpSlots extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		PrintStream out = new PrintStream(args[0]);
		int slot = Integer.parseInt(args[1]);
		TreeSet<String> used = new TreeSet<>();
		Language lang = currentProgram.getLanguage();
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			if (!block.isInitialized() || !block.getStart().getAddressSpace().isMemorySpace() ||
				block.getStart().getOffset() != 0) {
				continue;
			}
			Address base = block.getStart();
			for (long off = 0; off + slot <= block.getSize(); off += slot) {
				Address a = base.add(off);
				String text;
				int len = 0;
				try {
					ProcessorContextImpl ctx = new ProcessorContextImpl(lang);
					MemBuffer buf = new DumbMemBufferImpl(currentProgram.getMemory(), a);
					InstructionPrototype proto = lang.parse(buf, ctx, false);
					PseudoInstruction ins = new PseudoInstruction(currentProgram, a, proto, buf, ctx);
					text = ins.toString();
					len = ins.getLength();
					if (proto instanceof SleighInstructionPrototype sp) {
						collect(sp.getRootState(), used);
					}
				}
				catch (Exception e) {
					text = "BAD (" + String.valueOf(e.getMessage()).split("\n")[0] + ")";
				}
				out.printf("%08x %d %s%n", off, len, text);
			}
		}
		out.close();
		if (args.length > 2) {
			PrintStream c = new PrintStream(args[2]);
			used.forEach(c::println);
			c.close();
		}
	}

	private static void collect(ConstructState st, TreeSet<String> used) {
		if (st == null || st.getConstructor() == null) {
			return;
		}
		used.add(st.getConstructor().getSourceFile() + ":" + st.getConstructor().getLineno());
		for (int i = 0; i < st.getNumSubStates(); i++) {
			collect(st.getSubState(i), used);
		}
	}
}
