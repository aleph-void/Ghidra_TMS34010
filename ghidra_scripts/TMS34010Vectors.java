// Marks the TMS34010 trap vector table of a raw image: for each of the 32 vectors (bit address
// FFFFFFE0h - 32*N, Ghidra address 1FFFFFFCh - 4*N) that lies in initialized memory, labels the
// vector, converts the bit address it holds to a Ghidra address (bit address / 8), and
// disassembles and creates a function there. Run it after importing a ROM image that includes
// the top of the address space (for example a program ROM mapped at FF800000h, Ghidra address
// 1FF00000h).
//@category TMS34010

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;

public class TMS34010Vectors extends GhidraScript {

	private static final String[] NAMES = { "RESET", "INT1", "INT2", "TRAP3", "TRAP4", "TRAP5",
		"TRAP6", "TRAP7", "NMI", "HI", "DI", "WV", "TRAP12", "TRAP13", "TRAP14", "TRAP15", "TRAP16",
		"TRAP17", "TRAP18", "TRAP19", "TRAP20", "TRAP21", "TRAP22", "TRAP23", "TRAP24", "TRAP25",
		"TRAP26", "TRAP27", "TRAP28", "TRAP29", "ILLOP", "TRAP31" };

	@Override
	protected void run() throws Exception {
		Memory mem = currentProgram.getMemory();
		int n = 0;
		for (int t = 0; t < 32; t++) {
			Address v = toAddr(0x1ffffffcL - 4L * t);
			if (!mem.contains(v) || !mem.getBlock(v).isInitialized()) {
				continue;
			}
			long bit = mem.getInt(v) & 0xffffffffL;
			createLabel(v, "VECTOR_" + NAMES[t], true, SourceType.ANALYSIS);
			clearListing(v, v.add(3));
			createData(v, DWordDataType.dataType);
			Address target = toAddr((bit & 0xfffffff0L) >> 3);
			if (bit == 0 || bit == 0xffffffffL || !mem.contains(target)) {
				continue;
			}
			setEOLComment(v, String.format("-> bit address %08Xh = %s", bit, target));
			disassemble(target);
			if (getFunctionAt(target) == null) {
				createFunction(target, "TRAP_" + NAMES[t]);
			}
			n++;
		}
		println("TMS34010 vectors: " + n + " entry points");
	}
}
