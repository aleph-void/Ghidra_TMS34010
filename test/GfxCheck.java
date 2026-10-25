// Runs the TMS34010_sv graphics vectors (MIT, github.com/birdybro/TMS34010_sv, programs whose
// final state was recorded by MAME's TMS34010 core) in Ghidra's p-code emulator and compares the
// result with MAME's: A0-A14, B0-B14, ST, the six I/O registers and the 512 watched words.
// The program must be a blank raw image imported at address 0 (at least 0x1400 bytes).
// Script args: <mame_graphics_vectors.txt> <mame_graphics_expected.txt> <outfile>
// Output: one line per case: "<id> OK", "<id> OK-SCRATCH <fields>" (only B10-B14 differ: after
// FILL/PIXBLT these hold intermediate values the User's Guide leaves undefined; the MAME build
// the vectors were recorded with leaves its own working image there, Ghidra leaves them
// unchanged) or "<id> <field>=<ghidra>/<mame> ...".
//@category Testing

import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class GfxCheck extends GhidraScript {

	static class Case {
		int id;
		List<Integer> program = new ArrayList<>();
		TreeMap<Integer, Integer> memory = new TreeMap<>();
		int watchBase, watchWords;
		long pc, sp, st;
		long[] a = new long[15], b = new long[15];
		int[] io = new int[6];
		int[] mem;
	}

	private static final String[] IO_NAMES = { "DPYCTL", "CONTROL", "CONVSP", "CONVDP", "PSIZE", "PMASK" };
	private static final long[] IO_BYTE = { 0x18000010L, 0x18000016L, 0x18000026L, 0x18000028L, 0x1800002aL, 0x1800002cL };

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		Map<Integer, Case> cases = new TreeMap<>();
		Iterator<String> it = Files.readAllLines(Path.of(args[0])).iterator();
		it.next();
		while (it.hasNext()) {
			String[] h = it.next().trim().split("\\s+");
			if (!h[0].equals("CASE")) continue;
			Case c = new Case();
			c.id = Integer.parseInt(h[1], 16);
			int nprog = Integer.parseInt(h[2], 16);
			int nmem = Integer.parseInt(h[3], 16);
			c.watchBase = Integer.parseInt(h[4], 16);
			c.watchWords = Integer.parseInt(h[5], 16);
			it.next(); // PROGRAM
			for (int i = 0; i < nprog; i++) c.program.add(Integer.parseInt(it.next().trim(), 16));
			it.next(); // MEMORY
			for (int i = 0; i < nmem; i++) {
				String[] m = it.next().trim().split("\\s+");
				c.memory.put(Integer.parseInt(m[0], 16), Integer.parseInt(m[1], 16));
			}
			it.next(); // END
			cases.put(c.id, c);
		}
		it = Files.readAllLines(Path.of(args[1])).iterator();
		it.next();
		while (it.hasNext()) {
			String[] h = it.next().trim().split("\\s+");
			if (!h[0].equals("CASE")) continue;
			Case c = cases.get(Integer.parseInt(h[1], 16));
			c.pc = Long.parseLong(h[2], 16);
			c.sp = Long.parseLong(h[3], 16);
			c.st = Long.parseLong(h[4], 16);
			String[] a = it.next().trim().split("\\s+");
			String[] b = it.next().trim().split("\\s+");
			String[] io = it.next().trim().split("\\s+");
			String[] mem = it.next().trim().split("\\s+");
			for (int i = 0; i < 15; i++) {
				c.a[i] = Long.parseLong(a[i + 1], 16);
				c.b[i] = Long.parseLong(b[i + 1], 16);
			}
			for (int i = 0; i < 6; i++) c.io[i] = Integer.parseInt(io[i + 1], 16);
			c.mem = new int[mem.length - 1];
			for (int i = 1; i < mem.length; i++) c.mem[i - 1] = Integer.parseInt(mem[i], 16);
			it.next(); // END
		}
		PrintStream out = new PrintStream(args[2]);
		int ok = 0, scratch = 0;
		for (Case c : cases.values()) {
			String r = runCase(c);
			String rest = r.replaceAll(" B1[0-4]=[0-9a-f]+/[0-9a-f]+", "");
			if (r.isEmpty()) {
				ok++;
				out.println(c.id + " OK");
			}
			else if (rest.isEmpty()) {
				scratch++;
				out.println(c.id + " OK-SCRATCH" + r);
			}
			else {
				out.println(c.id + r);
			}
		}
		out.printf("graphics vectors: %d/%d identical to MAME, %d more identical except B10-B14, %d different%n",
			ok, cases.size(), scratch, cases.size() - ok - scratch);
		out.close();
	}

	private String runCase(Case c) throws Exception {
		EmulatorHelper emu = new EmulatorHelper(currentProgram);
		try {
			byte[] zero = new byte[0x2000];
			emu.writeMemory(toAddr(0), zero);
			emu.writeMemory(toAddr(0x18000000L), new byte[0x40]);
			for (int i = 0; i < c.program.size(); i++) writeWord(emu, 2L * i, c.program.get(i));
			for (Map.Entry<Integer, Integer> e : c.memory.entrySet()) writeWord(emu, 2L * e.getKey(), e.getValue());
			for (String r : new String[] { "SP", "N", "C", "Z", "V", "PBX", "IE", "FE0", "FE1", "FS1", "STX" })
				emu.writeRegister(r, 0);
			emu.writeRegister("FS0", 0x10);
			for (int i = 0; i < 15; i++) {
				emu.writeRegister("A" + i, 0);
				emu.writeRegister("B" + i, 0);
			}
			long end = 2L * (c.program.size() - 1);
			emu.writeRegister(emu.getPCRegister(), 0);
			int steps = 0;
			while (emu.getExecutionAddress().getOffset() != end && steps < 2000) {
				if (!emu.step(monitor)) {
					return " emulation stopped at " + emu.getExecutionAddress() + ": " + emu.getLastError();
				}
				steps++;
			}
			StringBuilder sb = new StringBuilder();
			if (emu.getExecutionAddress().getOffset() != end) sb.append(" did-not-finish");
			for (int i = 0; i < 15; i++) {
				cmp(sb, "A" + i, emu.readRegister("A" + i).longValue(), c.a[i]);
				cmp(sb, "B" + i, emu.readRegister("B" + i).longValue(), c.b[i]);
			}
			cmp(sb, "SP", emu.readRegister("SP").longValue(), c.sp);
			long st = (emu.readRegister("N").longValue() << 31) | (emu.readRegister("C").longValue() << 30) |
				(emu.readRegister("Z").longValue() << 29) | (emu.readRegister("V").longValue() << 28) |
				(emu.readRegister("PBX").longValue() << 25) | (emu.readRegister("IE").longValue() << 21) |
				(emu.readRegister("FE1").longValue() << 11) | (emu.readRegister("FS1").longValue() << 6) |
				(emu.readRegister("FE0").longValue() << 5) | emu.readRegister("FS0").longValue() |
				emu.readRegister("STX").longValue();
			cmp(sb, "ST", st, c.st);
			for (int i = 0; i < 6; i++) cmp(sb, IO_NAMES[i], readWord(emu, IO_BYTE[i]), c.io[i]);
			int bad = 0;
			StringBuilder mb = new StringBuilder();
			for (int i = 0; i < c.mem.length; i++) {
				long g = readWord(emu, 2L * (c.watchBase + i));
				if (g != c.mem[i]) {
					if (bad < 4) mb.append(String.format(" mem[%x]=%04x/%04x", c.watchBase + i, g, c.mem[i]));
					bad++;
				}
			}
			if (bad > 0) sb.append(" MEM(" + bad + " words)" + mb);
			return sb.toString();
		}
		finally {
			emu.dispose();
		}
	}

	private void cmp(StringBuilder sb, String name, long g, long m) {
		if ((g & 0xffffffffL) != (m & 0xffffffffL)) sb.append(String.format(" %s=%08x/%08x", name, g & 0xffffffffL, m & 0xffffffffL));
	}

	private void writeWord(EmulatorHelper emu, long byteAddr, int v) throws Exception {
		emu.writeMemory(toAddr(byteAddr), new byte[] { (byte) v, (byte) (v >> 8) });
	}

	private long readWord(EmulatorHelper emu, long byteAddr) throws Exception {
		byte[] b = emu.readMemory(toAddr(byteAddr), 2);
		return (b[0] & 0xff) | ((b[1] & 0xff) << 8);
	}
}
