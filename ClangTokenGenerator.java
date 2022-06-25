
/*
 * Ghidra Script by Xenios91
 * For Glyph
 */

//@keybinding
//@menupath
//@toolbar

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Arrays;
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
	private static final String URL = "localhost";
	private static final String STATUS_ENDPOINT = "/status";
	private static final String POST_FUNCTION_DETAILS = "/train";

	private class BinaryDetails {
		private String binaryName = null;
		private Map<String, List<FunctionDetails>> functionsMap = null;

		public BinaryDetails(final String binaryName, final Map<String, List<FunctionDetails>> functionsMap) {
			setBinaryName(binaryName);
			setFunctionsMap(functionsMap);
		}

		public String getBinaryName() {
			return this.binaryName;
		}

		public void setBinaryName(final String binaryName) {
			this.binaryName = binaryName;
		}

		public Map<String, List<FunctionDetails>> getFunctionsMap() {
			return this.functionsMap;
		}

		public void setFunctionsMap(final Map<String, List<FunctionDetails>> functionsMap) {
			this.functionsMap = functionsMap;
		}
	}

	private class FunctionDetails {
		private String lowAddress;
		private String highAddress;
		private List<String> tokenList;
		private int parameterCount;
		private String functionName;
		private String returnType;

		public String getLowAddress() {
			return this.lowAddress;
		}

		public void setLowAddress(final String lowAddress) {
			this.lowAddress = lowAddress;
		}

		public String getHighAddress() {
			return this.highAddress;
		}

		public void setHighAddress(final String highAddress) {
			this.highAddress = highAddress;
		}

		public List<String> getTokenList() {
			if (this.tokenList == null) {
				this.tokenList = new ArrayList<>();
			}
			return this.tokenList;
		}

		public void setTokenList(final List<String> tokenList) {
			this.tokenList = tokenList;
		}

		public int getParameterCount() {
			return this.parameterCount;
		}

		public void setParameterCount(final int parameterCount) {
			this.parameterCount = parameterCount;
		}

		public String getFunctionName() {
			return this.functionName;
		}

		public void setFunctionName(final String functionName) {
			this.functionName = functionName;
		}

		public String getReturnType() {
			return this.returnType;
		}

		public void setReturnType(final String returnType) {
			this.returnType = returnType;
		}
	}

	/**
	 * Decompile function.
	 *
	 * @param f the function to decompile.
	 * @return the high function of the decompiled function.
	 */
	public HighFunction decompileFunction(final Function f) {
		HighFunction hfunction = null;

		try {
			final DecompileResults dRes = this.decomplib.decompileFunction(f,
					this.decomplib.getOptions().getDefaultTimeout(), getMonitor());
			hfunction = dRes.getHighFunction();
		} catch (final Exception exc) {
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
	private DecompInterface setUpDecompiler(final Program program) {
		final DecompInterface decompInterface = new DecompInterface();

		DecompileOptions options;
		options = new DecompileOptions();
		final PluginTool tool = this.state.getTool();
		if (tool != null) {
			final OptionsService service = tool.getService(OptionsService.class);
			if (service != null) {
				final ToolOptions opt = service.getOptions("Decompiler");
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
	private static void generateAddressRange(final FunctionDetails functionDetails, final Function function) {
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
				final DecompileResults dr = this.decomplib.decompileFunction(function,
						ClangTokenGenerator.DECOMPILATION_TIMEOUT, null);
				final FunctionDetails functionDetails = new FunctionDetails();
				ClangTokenGenerator.generateAddressRange(functionDetails, function);
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

				functionDetails.setFunctionName(function.getName());
				if (function.getReturnType().toString().contains("undefined")) {
					functionDetails.setReturnType("undefined");
				} else {
					functionDetails.setReturnType(function.getReturnType().toString());
				}

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
	 * Removes the comments from functions.
	 *
	 * @param tokensList the tokens list to remove comments from
	 * @return the list with comments removed
	 */
	private List<String> removeComments(final List<String> tokensList) {
		boolean removedComment = false;
		final String tokensString = String.join(" ", tokensList);
		int commentStart = 0;
		int commentEnd = 0;
		final StringBuilder sb = new StringBuilder(tokensString);
		if (sb.toString().contains("WARNING")) {

		}
		if (tokensString.contains("/*")) {
			commentStart = tokensString.indexOf("/*");
			commentEnd = tokensString.indexOf("*/");
			if (commentEnd < commentStart) {
				sb.delete(commentEnd, commentEnd + 2);
			} else {
				sb.delete(commentStart, commentEnd + 2);
			}
			removedComment = true;
		}

		if (removedComment) {
			removeComments(Arrays.asList(sb.toString().split(" ")));
		}

		return Arrays.asList(sb.toString().split(" "));
	}

	/**
	 * Check if variable.
	 *
	 * @param token the token to determine if it is a variable
	 * @return true, if the token is a variable
	 */
	private boolean checkIfVariable(final String token) {
		return token.toLowerCase().matches("^(\\d{0,3}\\w{1})var\\d$")
				|| token.toLowerCase().matches("^(\\w{0,2})stack\\d{0,3}$");
	}

	/**
	 * Filter functions.
	 *
	 * @param functionsList the functions list to perform filtering on
	 */
	private void filterFunctions(final List<FunctionDetails> functionsList) {
		for (final FunctionDetails functionDetails : functionsList) {
			final List<String> tokensList = functionDetails.getTokenList();
			for (int i = 0; i < tokensList.size(); i++) {
				final String token = tokensList.get(i);
				if (token.contains("0x")) {
					tokensList.set(i, "HEX");
				} else if (token.startsWith("FUN_")) {
					tokensList.set(i, "FUNCTION");
				} else if (checkIfVariable(token)) {
					tokensList.set(i, "VARIABLE");
				} else if (token.toLowerCase().matches("undefined\\d$")) {
					tokensList.set(i, "undefined");
				}
			}
			final List<String> filteredTokensList = removeComments(tokensList);
			functionDetails.setTokenList(filteredTokensList);
		}
	}

	/**
	 * Creates the json.
	 *
	 * @param functionsMap a map of good and errored functions from analysis.
	 * @return a json of the functions map.
	 */
	private String createJson(final BinaryDetails binaryDetails) {
		final Gson gson = new Gson();
		String json = null;
		try {
			json = gson.toJson(binaryDetails);
		} catch (final Exception e) {
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
	private void sendData(final String data, final String endPoint) {
		final int portNumber = 5000;
		final String urlFormat = "http://%s:%s%s";
		int responseCode;

		try {
			final String url = String.format(urlFormat, ClangTokenGenerator.URL, portNumber, endPoint);

			final HttpClient httpClient = HttpClient.newBuilder().version(HttpClient.Version.HTTP_2).build();
			final HttpRequest request = HttpRequest.newBuilder().POST(HttpRequest.BodyPublishers.ofString(data))
					.uri(URI.create(url)).setHeader("User-Agent", "Ghidra")
					.header("Content-Type", "application/json; charset=UTF-8").build();
			final HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

			responseCode = response.statusCode();

			if (responseCode != 200) {
				println("An error has occured sending data.");
			}

		} catch (final IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
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
			final Map<String, List<FunctionDetails>> functionsMap = generateTokens();
			final List<FunctionDetails> functions = functionsMap.get(ClangTokenGenerator.FUNCTIONS_KEY);
			final List<FunctionDetails> erroredFunctions = functionsMap.get(ClangTokenGenerator.ERRORED_FUNCTIONS_KEY);
			functions.forEach(function -> printf("Function found: %s\n", function.getTokenList().toString()));
			erroredFunctions
					.forEach(function -> printf("Decompilation Error: %s\n", function.getTokenList().toString()));
			filterFunctions(functions);

			final BinaryDetails binaryDetails = new BinaryDetails(this.currentProgram.getName(), functionsMap);
			final String json = createJson(binaryDetails);

			if (json != null && !json.isBlank() && json.isEmpty()) {
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
