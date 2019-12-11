package burp;

import java.awt.Component;

import javax.swing.JLabel;
import javax.swing.JTabbedPane;

/**
 * 
 * Class of the UI
 *
 */
public class WSSecurityMainTab implements ITab {
	private WSSecurityMain mainTab;
	private JTabbedPane tabbedPane;

	public WSSecurityMainTab(IBurpExtenderCallbacks callbacks) {
		this.tabbedPane = new JTabbedPane();
		callbacks.customizeUiComponent(this.tabbedPane);
		callbacks.addSuiteTab(WSSecurityMainTab.this);

		this.mainTab = new WSSecurityMain(this, callbacks);
		this.tabbedPane.add(mainTab.getUiComponent());
		this.tabbedPane.setTabComponentAt(0, new JLabel("Configuration"));
	}

	public WSSecurityMain getTab() {
		return this.mainTab;
	}

	@Override
	public String getTabCaption() {
		return "WS-Security";
	}

	@Override
	public Component getUiComponent() {
		return this.tabbedPane;
	}
}
