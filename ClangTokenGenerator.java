//@category Saving.Throw
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.SymbolIterator;

public class ClangTokenGenerator extends GhidraScript {

	private class FunctionDetails {
		private String lowAddress;
		private String highAddress;
		private List<ClangNode> tokenList;

		public String getLowAddress() {
			return lowAddress;
		}

		public void setLowAddress(String lowAddress) {
			this.lowAddress = lowAddress;
		}

		public String getHighAddress() {
			return highAddress;
		}

		public void setHighAddress(String highAddress) {
			this.highAddress = highAddress;
		}

		public List<ClangNode> getTokenList() {
			if (tokenList == null) {
				this.tokenList = new ArrayList<>();
			}
			return tokenList;
		}

		public void setTokenList(List<ClangNode> tokenList) {
			this.tokenList = tokenList;
		}
	}

	private DecompInterface decomplib;
	private int decompilationTimeout = 60;

	public HighFunction decompileFunction(Function f) {
		HighFunction hfunction = null;

		try {
			DecompileResults dRes = this.decomplib.decompileFunction(f, this.decomplib.getOptions().getDefaultTimeout(),
					getMonitor());
			hfunction = dRes.getHighFunction();
		} catch (Exception exc) {
			printf("EXCEPTION IN DECOMPILATION!\n");
			exc.printStackTrace();
		}

		return hfunction;
	}

	/*
	 * set up the decompiler
	 */
	private DecompInterface setUpDecompiler(Program program) {
		DecompInterface decompInterface = new DecompInterface();

		DecompileOptions options;
		options = new DecompileOptions();
		PluginTool tool = this.state.getTool();
		if (tool != null) {
			OptionsService service = tool.getService(OptionsService.class);
			if (service != null) {
				ToolOptions opt = service.getOptions("Decompiler");
				options.grabFromToolAndProgram(null, opt, program);
			}
		}
		decompInterface.setOptions(options);

		decompInterface.toggleCCode(true);
		decompInterface.toggleSyntaxTree(true);
		decompInterface.setSimplificationStyle("decompile");

		return decompInterface;
	}

	private void generateAddressRange(FunctionDetails functionDetails, Function function) {
		functionDetails.setLowAddress(function.getBody().getMinAddress().toString());
		functionDetails.setHighAddress(function.getBody().getMaxAddress().toString());
	}

	private List<FunctionDetails> generateTokens() {
		List<FunctionDetails> functionDetailsList = new ArrayList<>();
		SymbolIterator symbolIter = this.currentProgram.getSymbolTable().getAllSymbols(true);

		while (symbolIter.hasNext()) {
			FunctionManager functionManager = this.getCurrentProgram().getFunctionManager();
			Function function = functionManager.getFunctionAt(symbolIter.next().getAddress());
			if (function != null && !function.isExternal()) {
				DecompileResults dr = decomplib.decompileFunction(function, this.decompilationTimeout, null);
				FunctionDetails functionDetails = new FunctionDetails();
				generateAddressRange(functionDetails, function);
				List<ClangNode> tokenList = new ArrayList<>();
				dr.getCCodeMarkup().flatten(tokenList);
				
				List<ClangNode> newTokenList = new ArrayList<>();
				tokenList.forEach(token -> {
					if (!token.toString().isBlank()) {
						newTokenList.add(token);
					}
				});
				functionDetails.setTokenList(newTokenList);
				functionDetailsList.add(functionDetails);
			}

		}
		return functionDetailsList;
	}

	@Override
	public void run() throws Exception {
		this.decomplib = setUpDecompiler(this.currentProgram);
		if (!this.decomplib.openProgram(this.currentProgram)) {
			printf("Decompiler error: %s\n", this.decomplib.getLastMessage());
		} else {
			List<FunctionDetails> functionDetails = generateTokens();
			functionDetails.forEach(x -> System.out.println(x.getTokenList()));
			System.out.println("Complete");
		}

	}
}
