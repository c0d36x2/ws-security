# Burp WS-Security
This extension calculate a valid WS security token for every request (In Proxy, Scanner, Intruder, Repeater, Sequencer, Extender), and replace variables in theses requests by the valid token.
It follow <a href="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">Web Services Security (WS-Security, WSS) published by OASIS</a>

## Using Burp WS-Security
<li>This extension only change requests targeting in sope item. So you need to add the target in the scope.</li>

<li>Go to the WSSecurity tab, fill the password field, choose if you need the nonce to be base64 encoded or not.</li>

<li>Click “Turn WS-Security ON”. Now, for every request in scope, a valid security token will be created.</li>

<li>In your request <ul><b>#WS-SecurityPasswordDigest</b> will be replaced by the Password Digest</ul><ul><b>#WS-SecurityNonce</b> will be replaced by the Nonce</ul><ul><b>#WS-SecurityCreated</b> will be replaced by the correct time</ul><ul><b>#WS-SecurityUUID</b> will be replaced by a random UUID</ul></li>

<li>This extension will log in the Extender UI every request after change if you need to debug.</li>

![Screenshot](https://raw.githubusercontent.com/RobinFassina-Moschini/Burp-WS-Security/master/images/screenshot.png)
