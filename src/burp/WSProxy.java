package burp;

import java.io.PrintWriter;
import java.net.URL;

public class WSProxy implements IHttpListener {
    private WSSecurityMainTab wsSecurityMainTabu;
    private IExtensionHelpers helpers;
    private Logger logger;
    private IBurpExtenderCallbacks callbacks;
    private WSSecurityGenerator wsSecurityGenerator;

    public WSProxy(WSSecurityMainTab wsSecurityMainTabu, WSSecurityGenerator wsSecurityGenerator, IBurpExtenderCallbacks callbacks) {
        this.wsSecurityMainTabu = wsSecurityMainTabu;
        this.helpers = callbacks.getHelpers();
        this.callbacks = callbacks;
        this.wsSecurityGenerator = wsSecurityGenerator;
        this.logger = new Logger(new PrintWriter(callbacks.getStdout(), true));
        Logger.setLogLevel(Logger.INFO);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, burp.IHttpRequestResponse messageInfo) {
    	logger.debug("Processing...");
        if (messageIsRequest) {
            logger.debug("Processing request...");
            byte[] requestBytes = messageInfo.getRequest();
            String request = new String(requestBytes);

            String extractedData;
            Boolean nonceBase64Encoded;
            WSSecurityMain wsSecurityMain = this.wsSecurityMainTabu.getTab();
            if (wsSecurityMain.shouldModifyRequests()) {       	
                URL url = this.helpers.analyzeRequest(messageInfo.getHttpService(), requestBytes).getUrl();
                if (this.callbacks.isInScope(url)) {
                    logger.debug("Request is in scope and WSSecurity tab is active.");

                    extractedData = wsSecurityMain.getDataToInsert();
                    nonceBase64Encoded = wsSecurityMain.getNonceData();
                    if (!extractedData.equals("")) {
                        logger.debug("Performing replacement...");
                        String[] res = wsSecurityGenerator.getWSSecurity(extractedData, nonceBase64Encoded);
                        request = request.replaceAll("#WS-SecurityPasswordDigest", res[2]);
                        request = request.replaceAll("#WS-SecurityNonce", res[1]);
                        request = request.replaceAll("#WS-SecurityCreated", res[0]);
                        request = request.replaceAll("#WS-SecurityUUID", res[3]);
                        logger.info(request);
                        logger.debug("Finished replacement.");
                        messageInfo.setRequest(request.getBytes());
                    } else {
                    	logger.debug("Password empty");
                    }
                }
            }
        }
    }
}
