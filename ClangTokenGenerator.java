/*
 * Ghidra Script by Xenios91
 * For Glyph
 */
//@keybinding
//@menupath
//@toolbar

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;

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

/**
 * The Class ClangTokenGenerator.
 */
public class ClangTokenGenerator extends GhidraScript {

	private DecompInterface decomplib;
	private static final int DECOMPILATION_TIMEOUT = 60;
	private static final String ERRORED_FUNCTIONS_KEY = "erroredFunctions";
	private static final String FUNCTIONS_KEY = "functions";
	private static final String URL = "http://localhost";
	private static final String STATUS_ENDPOINT = "/status";
	private static final String POST_FUNCTION_DETAILS = "/postFunctionDetails";

	private class BinaryDetails {
		private String binaryName = null;
		private Map<String, List<FunctionDetails>> functionsMap = null;

		public BinaryDetails(String binaryName, Map<String, List<FunctionDetails>> functionsMap) {
			setBinaryName(binaryName);
			setFunctionsMap(functionsMap);
		}

		public String getBinaryName() {
			return binaryName;
		}

		public void setBinaryName(String binaryName) {
			this.binaryName = binaryName;
		}

		public Map<String, List<FunctionDetails>> getFunctionsMap() {
			return functionsMap;
		}

		public void setFunctionsMap(Map<String, List<FunctionDetails>> functionsMap) {
			this.functionsMap = functionsMap;
		}
	}

	private class FunctionDetails {
		private String lowAddress;
		private String highAddress;
		private List<String> tokenList;
		private int parameterCount;

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

		public List<String> getTokenList() {
			if (tokenList == null) {
				this.tokenList = new ArrayList<>();
			}
			return tokenList;
		}

		public void setTokenList(List<String> tokenList) {
			this.tokenList = tokenList;
		}

		public int getParameterCount() {
			return parameterCount;
		}

		public void setParameterCount(int parameterCount) {
			this.parameterCount = parameterCount;
		}
	}

	/**
	 * Decompile function.
	 *
	 * @param f the function to decompile.
	 * @return the high function of the decompiled function.
	 */
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

	/**
	 * Sets the up decompiler.
	 *
	 * @param program the program to decompile.
	 * @return the decomp interface
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

	/**
	 * Generate address range.
	 *
	 * @param functionDetails a FunctionsDetails class to fill out the address space
	 *                        of its function.
	 * @param function        the function to retrieve the address space of.
	 */
	private void generateAddressRange(FunctionDetails functionDetails, Function function) {
		functionDetails.setLowAddress(function.getBody().getMinAddress().toString());
		functionDetails.setHighAddress(function.getBody().getMaxAddress().toString());
	}

	/**
	 * Generate tokens.
	 *
	 * @return A list of Clang Tokens
	 */
	private Map<String, List<FunctionDetails>> generateTokens() {
		sendData(String.format("{\"status\": \"generating tokens for: %s\"}", this.currentProgram.getName()),
				ClangTokenGenerator.STATUS_ENDPOINT);
		final Map<String, List<FunctionDetails>> functionsMap = Map.of(ClangTokenGenerator.FUNCTIONS_KEY,
				new ArrayList<>(), ClangTokenGenerator.ERRORED_FUNCTIONS_KEY, new ArrayList<>());
		final SymbolIterator symbolIter = this.currentProgram.getSymbolTable().getAllSymbols(true);
		final FunctionManager functionManager = this.getCurrentProgram().getFunctionManager();
		println("Retrieving all internal functions");
		symbolIter.forEachRemaining(symbol -> {

			final Function function = functionManager.getFunctionAt(symbol.getAddress());
			if (function != null && !function.isExternal()) {
				final DecompileResults dr = decomplib.decompileFunction(function,
						ClangTokenGenerator.DECOMPILATION_TIMEOUT, null);
				final FunctionDetails functionDetails = new FunctionDetails();
				generateAddressRange(functionDetails, function);
				final List<ClangNode> tokenList = new ArrayList<>();
				dr.getCCodeMarkup().flatten(tokenList);

				final List<String> newTokenList = new ArrayList<>();

				String key = null;

				if (tokenList.get(2).toString().contains("/*")) {
					key = ClangTokenGenerator.ERRORED_FUNCTIONS_KEY;
				} else {
					key = ClangTokenGenerator.FUNCTIONS_KEY;
				}

				tokenList.forEach(token -> {
					if (!token.toString().isBlank()) {
						newTokenList.add(token.toString());
					}
				});

				functionDetails.setParameterCount(function.getParameterCount());
				functionDetails.setTokenList(newTokenList);
				functionsMap.get(key).add(functionDetails);
			}
		});
		sendData(String.format("{\"status\": \"token generation complete for: %s\"}", this.currentProgram.getName()),
				ClangTokenGenerator.STATUS_ENDPOINT);
		return functionsMap;
	}

	/**
	 * Creates the json.
	 *
	 * @param functionsMap a map of good and errored functions from analysis.
	 * @return a json of the functions map.
	 */
	private String createJson(BinaryDetails binaryDetails) {
		Gson gson = new Gson();
		String json = null;
		try {
			json = gson.toJson(binaryDetails);
		} catch (Exception e) {
			println(e.toString());
		}
		return json;
	}

	/**
	 * Send data.
	 *
	 * @param data     the data to send to the server.
	 * @param endPoint the host name to send data do.
	 */
	private void sendData(String data, String endPoint) {
		final int portNumber = 8080;
		int responseCode;

		try {
			URL url = new URL(ClangTokenGenerator.URL + ":" + portNumber + endPoint);
			HttpURLConnection connection = (HttpURLConnection) url.openConnection();
			connection.setRequestMethod("POST");
			connection.setDoOutput(true);
			connection.setFixedLengthStreamingMode(data.length());
			connection.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
			connection.connect();
			try (OutputStream os = connection.getOutputStream()) {
				os.write(data.getBytes(StandardCharsets.UTF_8));
				os.flush();

				responseCode = connection.getResponseCode();

				if (responseCode != 200) {
					println("An error has occured sending data.");
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Run.
	 *
	 * @throws Exception the exception
	 */
	@Override
	public void run() throws Exception {
		sendData(String.format("{\"status\": \"processing\" \"name\": \"%s\"}", this.currentProgram.getName()),
				ClangTokenGenerator.STATUS_ENDPOINT);
		this.decomplib =

				setUpDecompiler(this.currentProgram);
		if (!this.decomplib.openProgram(this.currentProgram)) {
			printf("Decompiler error: %s\n", this.decomplib.getLastMessage());
		} else {
			Map<String, List<FunctionDetails>> functionsMap = generateTokens();
			List<FunctionDetails> functions = functionsMap.get(ClangTokenGenerator.FUNCTIONS_KEY);
			List<FunctionDetails> erroredFunctions = functionsMap.get(ClangTokenGenerator.ERRORED_FUNCTIONS_KEY);
			functions.forEach(function -> printf("Function found: %s\n", function.getTokenList().toString()));
			erroredFunctions
					.forEach(function -> printf("Decompilation Error: %s\n", function.getTokenList().toString()));

			BinaryDetails binaryDetails = new BinaryDetails(this.currentProgram.getName(), functionsMap);
			String json = createJson(binaryDetails);

			if (json != null && !json.isBlank()) {
				sendData(json, ClangTokenGenerator.POST_FUNCTION_DETAILS);
				sendData(String.format("{\"status\": \"complete\" \"name\": \"%s\"}", this.currentProgram.getName()),
						ClangTokenGenerator.STATUS_ENDPOINT);
			} else {
				sendData(String.format("{\"status\": \"failed\" \"name\": \"%s\"}", this.currentProgram.getName()),
						ClangTokenGenerator.STATUS_ENDPOINT);
			}
			println("Token Generation Complete");
		}

	}
}
