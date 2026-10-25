// Runs the p-code semantic tests produced by emu_tests.py in Ghidra's p-code emulator.
// The program must be emu.bin imported raw at address 0.
// Script args: <tests.txt> <outfile>
//   tests.txt lines: <name> <start-hex> <stop-hex> <init|-> <expect>
//   init/expect items, comma separated: <reg>=<hex> or @<byte-addr-hex>:<size>=<hex> (memory,
//   little endian). "ST" is the status register composed from the flag registers.
//   TMS34020 coprocessor: init CPIN=<hex>:<hex>... queues the values the coprocessor returns;
//   expect CPOUT=<hex>:<hex>... lists the values sent to it, CPCMD=<id>:<command>:<size> the last
//   command (all hex). IDLE's wait_for_interrupt returns at once.
//@category Testing

import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;

public class EmuCheck extends GhidraScript {

	private static final String[] ST_FIELDS = { "N", "C", "Z", "V", "PBX", "IE", "FE1", "FS1", "FE0", "FS0" };
	private static final int[] ST_SHIFT = { 31, 30, 29, 28, 25, 21, 11, 6, 5, 0 };

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		PrintStream out = new PrintStream(args[1]);
		int pass = 0, fail = 0;
		for (String line : Files.readAllLines(Path.of(args[0]))) {
			line = line.trim();
			if (line.isEmpty() || line.startsWith("#")) continue;
			String[] f = line.split("\\s+");
			String err = runOne(f);
			if (err == null) {
				pass++;
				out.println("PASS " + f[0]);
			}
			else {
				fail++;
				out.println("FAIL " + f[0] + ": " + err);
			}
		}
		out.printf("emulator tests: %d passed, %d failed%n", pass, fail);
		out.close();
	}

	private long readSt(EmulatorHelper emu) {
		long st = emu.readRegister("STX").longValue();
		for (int i = 0; i < ST_FIELDS.length; i++)
			st |= emu.readRegister(ST_FIELDS[i]).longValue() << ST_SHIFT[i];
		return st & 0xffffffffL;
	}

	private void writeSt(EmulatorHelper emu, long st) {
		for (int i = 0; i < ST_FIELDS.length; i++) {
			long w = ST_FIELDS[i].startsWith("FS") ? 0x1f : 1;
			emu.writeRegister(ST_FIELDS[i], (st >> ST_SHIFT[i]) & w);
		}
		emu.writeRegister("STX", st & 0x0ddff000L);
	}

	private String runOne(String[] f) throws Exception {
		Address start = toAddr(Long.parseUnsignedLong(f[1], 16));
		Address stop = toAddr(Long.parseUnsignedLong(f[2], 16));
		EmulatorHelper emu = new EmulatorHelper(currentProgram);
		ArrayDeque<Long> cpin = new ArrayDeque<>();
		List<String> cpout = new ArrayList<>();
		String[] cpcmd = { "" };
		if (currentProgram.getLanguageID().getIdAsString().startsWith("tms34020:")) {
		emu.registerCallOtherCallback("coprocessor_command", new BreakCallBack() {
			@Override
			public boolean pcodeCallback(PcodeOpRaw op) {
				var ms = emulate.getMemoryState();
				cpcmd[0] = String.format("%x:%x:%x", ms.getValue(op.getInput(1)),
					ms.getValue(op.getInput(2)), ms.getValue(op.getInput(3)));
				return true;
			}
		});
		emu.registerCallOtherCallback("coprocessor_write", new BreakCallBack() {
			@Override
			public boolean pcodeCallback(PcodeOpRaw op) {
				cpout.add(Long.toHexString(emulate.getMemoryState().getValue(op.getInput(2))));
				return true;
			}
		});
		emu.registerCallOtherCallback("coprocessor_read", new BreakCallBack() {
			@Override
			public boolean pcodeCallback(PcodeOpRaw op) {
				Long v = cpin.poll();
				emulate.getMemoryState().setValue(op.getOutput(), v == null ? 0 : v);
				return true;
			}
		});
		emu.registerCallOtherCallback("wait_for_interrupt", new BreakCallBack() {
			@Override
			public boolean pcodeCallback(PcodeOpRaw op) {
				return true;
			}
		});
		}
		try {
			for (int i = 0; i < 15; i++) {
				emu.writeRegister("A" + i, 0);
				emu.writeRegister("B" + i, 0);
			}
			emu.writeRegister("SP", 0x60000);
			writeSt(emu, 0x10);
			if (!f[3].equals("-")) {
				for (String kv : f[3].split(",")) {
					String[] p = kv.split("=");
					if (p[0].equals("CPIN")) {
						for (String x : p[1].split(":")) cpin.add(Long.parseUnsignedLong(x, 16));
						continue;
					}
					long v = Long.parseUnsignedLong(p[1], 16);
					if (p[0].startsWith("@")) {
						String[] as = p[0].substring(1).split(":");
						int size = Integer.parseInt(as[1]);
						byte[] b = new byte[size];
						for (int i = 0; i < size; i++) b[i] = (byte) (v >> (8 * i));
						emu.writeMemory(toAddr(Long.parseUnsignedLong(as[0], 16)), b);
					}
					else if (p[0].equals("ST")) {
						writeSt(emu, v);
					}
					else {
						emu.writeRegister(p[0], BigInteger.valueOf(v));
					}
				}
			}
			emu.writeRegister(emu.getPCRegister(), start.getOffset());
			int steps = 0;
			while (!emu.getExecutionAddress().equals(stop) && steps < 1000) {
				if (!emu.step(monitor)) {
					return "emulation stopped at " + emu.getExecutionAddress() + ": " + emu.getLastError();
				}
				steps++;
			}
			if (!emu.getExecutionAddress().equals(stop)) {
				return "did not reach " + stop + " in 1000 steps (at " + emu.getExecutionAddress() + ")";
			}
			StringBuilder bad = new StringBuilder();
			for (String kv : f[4].split(",")) {
				String[] p = kv.split("=");
				if (p[0].equals("CPOUT") || p[0].equals("CPCMD")) {
					String got = p[0].equals("CPCMD") ? cpcmd[0] : String.join(":", cpout);
					if (!got.equals(p[1])) bad.append(String.format(" %s=%s (want %s)", p[0], got, p[1]));
					continue;
				}
				BigInteger want = new BigInteger(p[1], 16);
				BigInteger got;
				if (p[0].startsWith("@")) {
					String[] as = p[0].substring(1).split(":");
					int size = Integer.parseInt(as[1]);
					byte[] b = emu.readMemory(toAddr(Long.parseUnsignedLong(as[0], 16)), size);
					long v = 0;
					for (int i = size - 1; i >= 0; i--) v = (v << 8) | (b[i] & 0xff);
					got = new BigInteger(Long.toUnsignedString(v));
				}
				else if (p[0].equals("ST")) {
					got = BigInteger.valueOf(readSt(emu));
				}
				else {
					Register r = currentProgram.getRegister(p[0]);
					BigInteger mask = BigInteger.ONE.shiftLeft(r.getBitLength()).subtract(BigInteger.ONE);
					want = want.and(mask);
					got = emu.readRegister(r).and(mask);
				}
				if (!want.equals(got)) bad.append(String.format(" %s=%x (want %x)", p[0], got, want));
			}
			return bad.length() == 0 ? null : bad.toString().trim();
		}
		finally {
			emu.dispose();
		}
	}
}
