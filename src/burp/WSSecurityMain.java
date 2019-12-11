package burp;

import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFormattedTextField;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JSpinner;
import javax.swing.SpinnerModel;
import javax.swing.SpinnerNumberModel;

/**
 * 
 * Class of the UI
 *
 */
public class WSSecurityMain implements ITab {

	/**
	 * Password
	 */
	private JPasswordField dataToInsert;

	private JPanel masterPane;
	private JButton modifyRequests;
	private JCheckBox hashPassword;
	private JCheckBox nonceBase64Button;
	private boolean nonceBase64;
	private boolean wsSecurityOn;
	private boolean passwordHashed;
	private JSpinner nonceSize;
	private JComboBox<String> hashsList;

	public WSSecurityMain(WSSecurityMainTab mainTabu, IBurpExtenderCallbacks callbacks) {
		this.masterPane = new JPanel();
		this.masterPane.setBorder(BorderFactory.createMatteBorder(5, 5, 5, 5, new Color(255, 255, 255)));
		this.masterPane.setLayout(new GridBagLayout());

		JPanel topPane = new JPanel();
		topPane.setLayout(new GridBagLayout());

		GridBagConstraints constraints = new GridBagConstraints();

		// Help
		JLabel helpLabel = new JLabel(
				"<html><body><p>This extension calculate a valid WS security token for every request,</p>"
						+ "<p>and replace variables in theses requests by the valid token in Proxy, Scanner, Intruder, Repeater, Sequencer and Extender.</p>"
						+ "<p>It follow Web Services Security (WS-Security, WSS) published by OASIS.</p>" + "<br>"
						+ "<p><b>Using Burp WS-Security</b></p>" + "<ol>"
						+ "    <li>This extension only change requests targeting in scope item. So you need to add the target in the scope.</li>"
						+ "    <li>Fill the password field, choose if you need the nonce to be base64 encoded or not and its size.</li>"
						+ "    <li>Click 'Turn WS-Security ON'. Now, for every request in scope, a valid security token will be created.</li>"
						+ "    <li>In your request <ul><b>#WS-SecurityPasswordDigest</b> will be replaced by the Password Digest</ul><ul><b>#WS-SecurityNonce</b> will be replaced by the Nonce</ul><ul><b>#WS-SecurityCreated</b> will be replaced by the correct time</ul><ul><b>#WS-SecurityUUID</b> will be replaced by a random UUID</ul></li>"
						+ "    <li>This extension will log in the Extender UI every request after change if you need to debug.</li>"
						+ "</ol><br>"
						+ "Unless you have specific needs, you shouldn't touch the advanced option and not enable the hash of the password.<br><br></body></html>");
		constraints.gridx = 0;
		constraints.gridy = 0;
		constraints.anchor = GridBagConstraints.NORTHWEST;
		constraints.fill = GridBagConstraints.NONE;
		topPane.add(helpLabel, constraints);

		constraints.gridx = 0;
		constraints.gridy = 0;
		constraints.anchor = GridBagConstraints.NORTHWEST;
		constraints.fill = GridBagConstraints.NONE;
		masterPane.add(topPane, constraints);

		JPanel passwordPane = new JPanel();
		passwordPane.setLayout(new GridBagLayout());

		// Create password field
		JLabel passwordLabel = new JLabel("Password:    ");
		constraints.gridx = 0;
		constraints.gridy = 0;
		constraints.anchor = GridBagConstraints.WEST;
		constraints.fill = GridBagConstraints.NONE;
		passwordPane.add(passwordLabel, constraints);

		this.dataToInsert = new JPasswordField(32);
		constraints.gridx = 1;
		constraints.gridy = 0;
		constraints.fill = GridBagConstraints.HORIZONTAL;
		passwordPane.add(dataToInsert, constraints);

		constraints.gridx = 0;
		constraints.gridy = 1;
		constraints.anchor = GridBagConstraints.SOUTHWEST;
		constraints.fill = GridBagConstraints.NONE;
		masterPane.add(passwordPane, constraints);

		JPanel noncePane = new JPanel();
		noncePane.setLayout(new GridBagLayout());

		// Create nonce field
		JLabel nonceLabel = new JLabel("Nonce: (ex: 'dGhpc0lzQU5vbmNlCg==')    ");
		constraints.gridx = 0;
		constraints.gridy = 0;
		constraints.anchor = GridBagConstraints.WEST;
		constraints.fill = GridBagConstraints.NONE;
		noncePane.add(nonceLabel, constraints);

		// Create nonce size field
		JLabel sizeLabel = new JLabel("Size:");
		constraints.gridx = 1;
		constraints.gridy = 0;
		constraints.anchor = GridBagConstraints.WEST;
		constraints.fill = GridBagConstraints.NONE;
		noncePane.add(sizeLabel, constraints);

		SpinnerModel sm = new SpinnerNumberModel(8, 1, 999, 1);
		this.nonceSize = new JSpinner(sm);
		this.nonceSize.setSize(3000, 2500);
		Component mySpinnerEditor = this.nonceSize.getEditor();
		JFormattedTextField jftf = ((JSpinner.DefaultEditor) mySpinnerEditor).getTextField();
		jftf.setColumns(3);
		constraints.gridx = 2;
		constraints.gridy = 0;
		constraints.fill = GridBagConstraints.NONE;
		noncePane.add(this.nonceSize, constraints);

		JLabel space = new JLabel("    ");
		constraints.gridx = 3;
		constraints.gridy = 0;
		constraints.anchor = GridBagConstraints.WEST;
		constraints.fill = GridBagConstraints.NONE;
		noncePane.add(space, constraints);

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
					nonceLabel.setText("Nonce: (ex: 'dGhpc0lzQU5vbmNlCg==')    ");
				} else {
					nonceBase64Button.setSelected(false);
					nonceLabel.setText("Nonce: (ex: 'thisIsANonce')    ");
				}
			}

			@Override
			public void mouseEntered(MouseEvent e) {

			}

			@Override
			public void mouseExited(MouseEvent e) {

			}
		});
		constraints.gridx = 4;
		constraints.gridy = 0;
		noncePane.add(nonceButtonPanel, constraints);

		constraints.gridx = 0;
		constraints.gridy = 1;
		constraints.anchor = GridBagConstraints.WEST;
		constraints.fill = GridBagConstraints.NONE;
		noncePane.add(space, constraints);

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
		constraints.gridy = 2;
		constraints.anchor = GridBagConstraints.SOUTHWEST;
		noncePane.add(buttonPanel, constraints);

		constraints.gridx = 0;
		constraints.gridy = 2;
		constraints.anchor = GridBagConstraints.SOUTHWEST;
		constraints.fill = GridBagConstraints.NONE;
		masterPane.add(noncePane, constraints);

		// Advanced Option
		JPanel advancedPane = new JPanel();
		advancedPane.setLayout(new GridBagLayout());
		advancedPane.setBorder(BorderFactory.createMatteBorder(5, 5, 5, 5, new Color(169, 169, 169)));

		JPanel advancedButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEADING));
		advancedButtonPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
		JLabel advancedLabel = new JLabel("Advanced Options:");

		advancedButtonPanel.add(advancedLabel);
		constraints.gridx = 0;
		constraints.gridy = 0;
		constraints.anchor = GridBagConstraints.SOUTHWEST;
		advancedPane.add(advancedButtonPanel, constraints);

		// Password hashing
		JPanel passwordHashing = new JPanel(new FlowLayout(FlowLayout.LEADING));
		passwordHashing.setAlignmentX(Component.LEFT_ALIGNMENT);
		this.hashPassword = new JCheckBox("Password need to be hashed    ");
		this.hashPassword.setSelected(false);
		this.passwordHashed = false;
		passwordHashing.add(this.hashPassword);

		this.hashPassword.addMouseListener(new MouseListener() {
			@Override
			public void mouseClicked(MouseEvent e) {

			}

			@Override
			public void mousePressed(MouseEvent e) {

			}

			@Override
			public void mouseReleased(MouseEvent e) {
				// Change button state
				passwordHashed = !passwordHashed;

				// Change button appearance
				if (passwordHashed) {
					hashPassword.setSelected(true);
				} else {
					hashPassword.setSelected(false);
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
		constraints.gridy = 1;
		constraints.anchor = GridBagConstraints.SOUTHWEST;
		advancedPane.add(passwordHashing, constraints);

		// Dropdown list to select hashing
		JLabel hashLabel = new JLabel("Hash: ");
		constraints.gridx = 1;
		constraints.gridy = 1;
		constraints.anchor = GridBagConstraints.SOUTHWEST;
		advancedPane.add(hashLabel, constraints);

		String[] hashs = new String[] { "SHA-1", "SHA-256", "MD5" };
		hashsList = new JComboBox<>(hashs);
		constraints.gridx = 2;
		constraints.gridy = 1;
		advancedPane.add(hashsList, constraints);

		constraints.gridx = 0;
		constraints.gridy = 3;
		constraints.anchor = GridBagConstraints.SOUTHWEST;
		constraints.fill = GridBagConstraints.NONE;
		masterPane.add(advancedPane, constraints);

		callbacks.customizeUiComponent(masterPane);
	}

	/**
	 * @return the password enter by the user
	 */
	public String getDataToInsert() {
		String string = new String(this.dataToInsert.getPassword());
		return string;
	}

	/**
	 * @return if the nonce is base64 encoded
	 */
	public boolean getNonceData() {
		return this.nonceBase64;
	}

	/**
	 * @return the nonce size
	 */
	public int getNonceSize() {
		return (int) this.nonceSize.getValue();
	}

	/**
	 * @return if the password should be hashed
	 */
	public boolean getNeedHashing() {
		return this.passwordHashed;
	}

	/**
	 * @return the hashing method
	 */
	public String getHash() {
		return (String) this.hashsList.getSelectedItem();
	}

	/**
	 * @return true if the user has made the extension currently active
	 */
	public boolean shouldModifyRequests() {
		return this.wsSecurityOn;
	}

	@Override
	public Component getUiComponent() {
		return this.masterPane;
	}

	@Override
	public String getTabCaption() {
		return "start";
	}
}
