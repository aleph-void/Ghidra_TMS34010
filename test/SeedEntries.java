// Pre-analysis script for raw images: disassemble at each given address, make it a function
// and an external entry point, so auto-analysis has somewhere to start.
// Script args: <address-hex> ...
//@category Testing

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class SeedEntries extends GhidraScript {

	@Override
	protected void run() throws Exception {
		for (String s : getScriptArgs()) {
			Address a = toAddr(Long.decode(s));
			disassemble(a);
			createFunction(a, null);
			currentProgram.getSymbolTable().addExternalEntryPoint(a);
		}
	}
}
