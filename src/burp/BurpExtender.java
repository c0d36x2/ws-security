package burp;

public class BurpExtender implements burp.IBurpExtender
{

    @Override
    public void registerExtenderCallbacks(burp.IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("WS-Security");
        
        WSSecurityGenerator wsSecurityGenerator = new WSSecurityGenerator(callbacks);
        WSSecurityMainTab wsSecurityMainTabu = new WSSecurityMainTab(callbacks);
        WSProxy wsProxy = new WSProxy(wsSecurityMainTabu, wsSecurityGenerator, callbacks);

        // Register WSSecurity as an HTTP listener
        callbacks.registerHttpListener(wsProxy);
    }
}