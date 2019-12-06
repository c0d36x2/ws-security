package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

public class WSSecurityMain implements ITab {

    private JPasswordField dataToInsert;
    private JPanel topPane;
    private JButton modifyRequests;
    private JCheckBox nonceBase64Button;
    private boolean nonceBase64;
    private boolean wsSecurityOn;
    
    public WSSecurityMain(WSSecurityMainTab mainTabu, IBurpExtenderCallbacks callbacks) {
        this.topPane = new JPanel();
    	this.topPane.setBorder(BorderFactory.createMatteBorder(5,5,5, 5, new Color(255,255,255)));
    	this.topPane.setLayout(new GridBagLayout());
        GridBagConstraints constraints = new GridBagConstraints();
        
        JLabel helpLabel = new JLabel("<html><body><p>This extension calculate a valid WS security token for every request (In Proxy, Scanner, Intruder, Repeater, Sequencer, Extender), and replace variables in theses requests by the valid token.</p>" + 
        		"<p>It follow <a href=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">Web Services Security (WS-Security, WSS) published by OASIS</a>" + 
        		"<p><b>Using Burp WS-Security</b></p>" + 
        		"<ol>" + 
        		"    <li>This extension only change requests targeting in sope item. So you need to add the target in the scope.</li>" + 
        		"    <li>Fill the password field, choose if you need the nonce to be base64 encoded or not.</li>" + 
        		"    <li>Click “Turn WS-Security ON”. Now, for every request in scope, a valid security token will be created.</li>" + 
        		"    <li>In your request <ul><b>#WS-SecurityPasswordDigest</b> will be replaced by the Password Digest</ul><ul><b>#WS-SecurityNonce</b> will be replaced by the Nonce</ul><ul><b>#WS-SecurityCreated</b> will be replaced by the correct time</ul><ul><b>#WS-SecurityUUID</b> will be replaced by a random UUID</ul></li>" + 
        		"    <li>This extension will log in the Extender UI every request after change if you need to debug.</li>" + 
        		"</ol></body></html>");
        constraints.gridx = 0;
        constraints.gridy = 0;
        constraints.anchor = GridBagConstraints.NORTHWEST;
        constraints.fill = GridBagConstraints.NONE;
        topPane.add(helpLabel, constraints);
        
        // Create password field
        JLabel passwordLabel = new JLabel("Password:");
        constraints.gridx = 0;
        constraints.gridy = 3;
        constraints.anchor = GridBagConstraints.WEST;
        constraints.fill = GridBagConstraints.NONE;
        topPane.add(passwordLabel, constraints);
        
        this.dataToInsert = new JPasswordField(32);
        constraints.gridx = 1;
        constraints.gridy = 3;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        topPane.add(dataToInsert, constraints);
        
     
        
     // Create nonce field
        JLabel nonceLabel = new JLabel("Nonce: (ex: 'dGhpc0lzQU5vbmNlCg==')");
        constraints.gridx = 0;
        constraints.gridy = 6;
        constraints.anchor = GridBagConstraints.WEST;
        constraints.fill = GridBagConstraints.NONE;
        topPane.add(nonceLabel, constraints);
        
     // Made button to dictate whether or not the nonce is base64 encoded
        JPanel nonceButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEADING));
        nonceButtonPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        this.nonceBase64Button = new JCheckBox("Base64 encoded");
        this.nonceBase64Button.setBackground(Color.LIGHT_GRAY);
        this.nonceBase64Button.setSelected(true);
        this.nonceBase64 = true;
        nonceButtonPanel.add(this.nonceBase64Button);

        this.nonceBase64Button.addMouseListener(new MouseListener() {
            @Override
            public void mouseClicked(MouseEvent e) {

            }

            @Override
            public void mousePressed(MouseEvent e) {

            }

            @Override
            public void mouseReleased(MouseEvent e) {
            	nonceBase64 = !nonceBase64;

                if (nonceBase64) {
                	nonceBase64Button.setSelected(true);
                	nonceLabel.setText("Nonce: (ex: 'dGhpc0lzQU5vbmNlCg==')");
                } else {
                	nonceBase64Button.setSelected(false);
                	nonceLabel.setText("Nonce: (ex: 'thisIsANonce')");
                }
            }

            @Override
            public void mouseEntered(MouseEvent e) {

            }

            @Override
            public void mouseExited(MouseEvent e) {

            }
        });
        constraints.gridx = 1;
        constraints.gridy = 6;
        topPane.add(nonceButtonPanel, constraints);
        
     // Made button to dictate whether or not the extension is active
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEADING));
        buttonPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        this.modifyRequests = new JButton("Turn WS-Security on");
        this.modifyRequests.setBackground(Color.LIGHT_GRAY);
        this.wsSecurityOn = false;
        buttonPanel.add(this.modifyRequests);

        this.modifyRequests.addMouseListener(new MouseListener() {
            @Override
            public void mouseClicked(MouseEvent e) {

            }

            @Override
            public void mousePressed(MouseEvent e) {

            }

            @Override
            public void mouseReleased(MouseEvent e) {
                // Change button state
                wsSecurityOn = !wsSecurityOn;

                // Change button appearance
                if (wsSecurityOn) {
                    modifyRequests.setBackground(Color.GRAY);
                    modifyRequests.setText("Turn WS-Security off");
                } else {
                    modifyRequests.setBackground(Color.LIGHT_GRAY);
                    modifyRequests.setText("Turn WS-Security on");
                }
            }

            @Override
            public void mouseEntered(MouseEvent e) {

            }

            @Override
            public void mouseExited(MouseEvent e) {

            }
        });
        constraints.gridx = 0;
        constraints.gridy = 9;
        topPane.add(buttonPanel, constraints);
        
        callbacks.customizeUiComponent(this.topPane);
    }

    public String getDataToInsert() {
    	String string = new String(this.dataToInsert.getPassword());
        return string;
    }
    
    public boolean getNonceData() {
        return this.nonceBase64;
    }

    public void setDataToInsert(String data) {
        this.dataToInsert.setText(data);
    }
    
 // Returns true if the user has made the extension currently active
    public boolean shouldModifyRequests() {
        return this.wsSecurityOn;
    }
    
    @Override
    public Component getUiComponent() {
    	return this.topPane;
    }

    @Override
	public String getTabCaption() {
		return "start";
	}
}
