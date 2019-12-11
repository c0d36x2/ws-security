package burp;

import java.io.PrintWriter;
import java.net.URL;

/**
 * 
 * This class intercept the request and replace the variable by the tokens
 *
 */
public class WSProxy implements IHttpListener {
	private WSSecurityMainTab wsSecurityMainTabu;
	private IExtensionHelpers helpers;
	private Logger logger;
	private IBurpExtenderCallbacks callbacks;
	private WSSecurityGenerator wsSecurityGenerator;

	public WSProxy(WSSecurityMainTab wsSecurityMainTabu, WSSecurityGenerator wsSecurityGenerator,
			IBurpExtenderCallbacks callbacks) {
		this.wsSecurityMainTabu = wsSecurityMainTabu;
		this.helpers = callbacks.getHelpers();
		this.callbacks = callbacks;
		this.wsSecurityGenerator = wsSecurityGenerator;
		this.logger = new Logger(new PrintWriter(callbacks.getStdout(), true));
		Logger.setLogLevel(Logger.INFO);
	}

	/**
	 * Replace the values in the request
	 */
	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, burp.IHttpRequestResponse messageInfo) {
		logger.debug("Processing...");
		// Process only if it's a request
		if (messageIsRequest) {
			logger.debug("Processing request...");
			byte[] requestBytes = messageInfo.getRequest();
			String request = new String(requestBytes);

			String extractedData;
			boolean nonceBase64Encoded;
			int nonceSize;
			String hashing = "";
			boolean pwdNeedHashing;
			WSSecurityMain wsSecurityMain = this.wsSecurityMainTabu.getTab();
			// Replace only if WS-Security is on
			if (wsSecurityMain.shouldModifyRequests()) {
				URL url = this.helpers.analyzeRequest(messageInfo.getHttpService(), requestBytes).getUrl();
				// Verify that the request is in the scope
				if (this.callbacks.isInScope(url)) {
					logger.debug("Request is in scope and WSSecurity tab is active.");

					extractedData = wsSecurityMain.getDataToInsert();
					nonceBase64Encoded = wsSecurityMain.getNonceData();
					nonceSize = wsSecurityMain.getNonceSize();
					pwdNeedHashing = wsSecurityMain.getNeedHashing();
					hashing = wsSecurityMain.getHash();
					// Verify that the password is not empty
					if (!extractedData.equals("")) {
						logger.debug("Performing replacement...");
						// Calculate all the security tokens
						String[] res = wsSecurityGenerator.getWSSecurity(extractedData, nonceBase64Encoded, nonceSize,
								pwdNeedHashing, hashing);
						request = request.replaceAll("#WS-SecurityPasswordDigest", res[2]);
						request = request.replaceAll("#WS-SecurityNonce", res[1]);
						request = request.replaceAll("#WS-SecurityCreated", res[0]);
						request = request.replaceAll("#WS-SecurityUUID", res[3]);
						logger.info(request);
						logger.debug("Finished replacement.");
						messageInfo.setRequest(request.getBytes());
					} else {
						logger.info("Password empty");
					}
				}
			}
		}
	}
}
