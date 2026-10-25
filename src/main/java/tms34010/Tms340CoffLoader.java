/* Licensed under the Apache License, Version 2.0 (see LICENSE). Ghidra-Rare addition. */
package tms34010;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Loader for TI TMS340 family COFF files (the GSPA assembler's objects and the GSPLNK linker's
 * executables, magic 0090h). TMS340 COFF stores section addresses, sizes, symbol values and
 * relocation addresses in bits; this loader divides them by 8, the module's address mapping
 * (Ghidra address = bit address / 8).
 *
 * Executables (F_RELFLG set) are loaded at their linked addresses. Relocatable objects get their
 * sections placed one after another from address 0 (bit address 0), and the 32-bit absolute
 * relocations (type 11h, R_RELLONG) against sections are applied; relocations against undefined
 * symbols are reported.
 */
public class Tms340CoffLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "TMS340 COFF";
	private static final int MAGIC = 0x0090;
	private static final int F_RELFLG = 0x0001;
	private static final int STYP_TEXT = 0x20, STYP_DATA = 0x40, STYP_BSS = 0x80;
	private static final int STYP_DSECT = 0x01, STYP_NOLOAD = 0x02, STYP_COPY = 0x10;
	private static final int R_RELLONG = 0x11;

	private static class Section {
		String name;
		long vaddr, size, scnptr, relptr;
		int nreloc, flags;
		long base; // bit address the section is loaded at
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 50;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		if (provider.length() < 20) {
			return specs;
		}
		BinaryReader r = new BinaryReader(provider, true);
		int magic = r.readUnsignedShort(0);
		int nscns = r.readUnsignedShort(2);
		int opthdr = r.readUnsignedShort(16);
		if (magic != MAGIC || nscns == 0 || nscns > 1000 || (opthdr != 0 && opthdr != 28) ||
			20L + opthdr + 40L * nscns > provider.length()) {
			return specs;
		}
		specs.add(new LoadSpec(this, 0,
			new LanguageCompilerSpecPair("tms34010:LE:32:default", "default"), true));
		specs.add(new LoadSpec(this, 0,
			new LanguageCompilerSpecPair("tms34010:LE:32:default", "tic"), false));
		// TMS34020 code uses the same COFF format; the header does not tell the two apart
		specs.add(new LoadSpec(this, 0,
			new LanguageCompilerSpecPair("tms34020:LE:32:default", "default"), false));
		specs.add(new LoadSpec(this, 0,
			new LanguageCompilerSpecPair("tms34020:LE:32:default", "tic"), false));
		return specs;
	}

	@Override
	protected void load(Program program, Loader.ImporterSettings settings)
			throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();
		BinaryReader r = new BinaryReader(provider, true);
		int nscns = r.readUnsignedShort(2);
		long symptr = r.readUnsignedInt(8);
		int nsyms = r.readInt(12);
		int opthdr = r.readUnsignedShort(16);
		int flags = r.readUnsignedShort(18);
		boolean relocatable = (flags & F_RELFLG) == 0;
		long entry = opthdr == 28 ? r.readUnsignedInt(20 + 16) : 0;

		List<Section> sections = new ArrayList<>();
		long next = 0;
		for (int i = 0; i < nscns; i++) {
			long o = 20 + opthdr + 40L * i;
			Section s = new Section();
			s.name = r.readAsciiString(o, 8).trim();
			s.vaddr = r.readUnsignedInt(o + 12);
			s.size = r.readUnsignedInt(o + 16);
			s.scnptr = r.readUnsignedInt(o + 20);
			s.relptr = r.readUnsignedInt(o + 24);
			s.nreloc = r.readUnsignedShort(o + 32);
			s.flags = r.readInt(o + 36);
			if (relocatable) {
				s.base = next;
				next += (s.size + 15) & ~15L;
			}
			else {
				s.base = s.vaddr;
			}
			sections.add(s);
		}

		Memory mem = program.getMemory();
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Map<Section, MemoryBlock> blocks = new HashMap<>();
		for (Section s : sections) {
			monitor.checkCancelled();
			if (s.size == 0 || (s.flags & (STYP_DSECT | STYP_NOLOAD | STYP_COPY)) != 0) {
				continue;
			}
			if ((s.size & 7) != 0 || (s.base & 7) != 0) {
				log.appendMsg(NAME, "section " + s.name + " is not byte aligned; rounded");
			}
			Address start = space.getAddress(s.base >> 3);
			long bytes = (s.size + 7) >> 3;
			boolean bss = (s.flags & STYP_BSS) != 0 || s.scnptr == 0;
			boolean x = (s.flags & STYP_TEXT) != 0;
			try {
				MemoryBlock b;
				if (bss) {
					b = MemoryBlockUtils.createUninitializedBlock(program, false, s.name, start,
						bytes, "", NAME, true, true, x, log);
				}
				else {
					try (InputStream in = provider.getInputStream(s.scnptr)) {
						b = MemoryBlockUtils.createInitializedBlock(program, false, s.name, start, in,
							bytes, "", NAME, true, true, x, log,
							monitor);
					}
				}
				if (b != null) {
					blocks.put(s, b);
				}
			}
			catch (Exception e) {
				log.appendMsg(NAME, "cannot create block " + s.name + ": " + e.getMessage());
			}
		}

		// symbols: 18-byte entries; long names in the string table after the symbols
		long strtab = symptr + 18L * nsyms;
		SymbolTable st = program.getSymbolTable();
		List<long[]> symInfo = new ArrayList<>(); // value(bits), section number
		for (int i = 0; i < nsyms; i++) {
			long o = symptr + 18L * i;
			String name;
			if (r.readInt(o) == 0) {
				name = r.readAsciiString(strtab + r.readUnsignedInt(o + 4));
			}
			else {
				name = r.readAsciiString(o, 8).trim();
			}
			long value = r.readUnsignedInt(o + 8);
			int scnum = r.readShort(o + 12);
			int sclass = r.readUnsignedByte(o + 16);
			int naux = r.readUnsignedByte(o + 17);
			symInfo.add(new long[] { value, scnum });
			long addr = value;
			if (scnum > 0 && scnum <= sections.size()) {
				Section s = sections.get(scnum - 1);
				if (relocatable) {
					addr = s.base + (value - s.vaddr);
				}
			}
			boolean label = (sclass == 2 || sclass == 3 && naux == 0 || sclass == 6) && scnum != 0 &&
				!name.isEmpty() && !name.startsWith(".");
			if (label && (addr & 7) == 0) {
				try {
					Address a = space.getAddress(addr >> 3);
					if (mem.contains(a)) {
						st.createLabel(a, name, SourceType.IMPORTED);
						if (sclass == 2) {
							st.addExternalEntryPoint(a);
						}
					}
				}
				catch (Exception e) {
					log.appendMsg(NAME, "symbol " + name + ": " + e.getMessage());
				}
			}
			for (int k = 0; k < naux; k++) {
				symInfo.add(new long[] { 0, 0 });
			}
			i += naux;
		}

		// relocations (relocatable objects only)
		if (relocatable) {
			for (Section s : sections) {
				for (int k = 0; k < s.nreloc; k++) {
					long o = s.relptr + 10L * k;
					long vaddr = r.readUnsignedInt(o);
					int symndx = r.readInt(o + 4);
					int type = r.readUnsignedShort(o + 8);
					long at = s.base + (vaddr - s.vaddr);
					Address a = space.getAddress(at >> 3);
					if (type != R_RELLONG || (at & 7) != 0) {
						log.appendMsg(NAME, String.format("relocation type %02x at %s not applied", type, a));
						continue;
					}
					long delta;
					if (symndx == -1) {
						delta = s.base - s.vaddr;
					}
					else if (symndx >= 0 && symndx < symInfo.size() && symInfo.get(symndx)[1] > 0 &&
						symInfo.get(symndx)[1] <= sections.size()) {
						Section t = sections.get((int) symInfo.get(symndx)[1] - 1);
						delta = t.base - t.vaddr;
					}
					else {
						log.appendMsg(NAME, "relocation at " + a + " refers to an undefined symbol");
						continue;
					}
					try {
						int v = mem.getInt(a, false);
						mem.setInt(a, (int) (v + delta), false);
						program.getRelocationTable().add(a,
							ghidra.program.model.reloc.Relocation.Status.APPLIED, type,
							new long[] { symndx }, 4, null);
					}
					catch (Exception e) {
						log.appendMsg(NAME, "relocation at " + a + ": " + e.getMessage());
					}
				}
			}
		}

		if (entry != 0 && (entry & 7) == 0) {
			Address a = space.getAddress(entry >> 3);
			if (mem.contains(a)) {
				st.addExternalEntryPoint(a);
				try {
					st.createLabel(a, "entry", SourceType.IMPORTED);
				}
				catch (Exception e) {
					// ignore
				}
			}
		}
	}
}
