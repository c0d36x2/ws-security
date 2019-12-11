package burp;

import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.TimeZone;
import java.util.UUID;

/**
 * 
 * This class generate a WS Security token
 *
 */
public class WSSecurityGenerator {
	private Logger logger;

	/**
	 * Link the logger
	 */
	public WSSecurityGenerator(IBurpExtenderCallbacks callbacks) {
		this.logger = new Logger(new PrintWriter(callbacks.getStdout(), true));
		Logger.setLogLevel(Logger.INFO);
	}

	/**
	 * Calculate the password digest from the nonce, timestamp and password
	 * 
	 * @param nonceB64           the nonce
	 * @param timestamp          the timestamp of creation
	 * @param pwd                the password
	 * @param nonceBase64Encoded Should the nonce be base64 encoded?
	 * @param pwdNeedHashing     Should the password be hashed?
	 * @param hashing            What hash use for the password?
	 * @return PasswordDigest
	 */
	public static String password_digest(String nonceB64, String timestamp, String pwd, boolean nonceBase64Encoded,
			boolean pwdNeedHashing, String hashing) {
		String passwdDigest = null;
		MessageDigest hashPwd = null;
		MessageDigest result = null;
		byte[] nonce = null;
		byte[] timeByte = null;
		byte[] passwd = null;
		try {
			hashPwd = MessageDigest.getInstance(hashing);
			result = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		// hash the password if needed or use it as clairtext
		if (pwdNeedHashing) {
			try {
				hashPwd.update(pwd.getBytes("UTF-8"));
				passwd = hashPwd.digest();
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
		} else {
			try {
				passwd = pwd.getBytes("UTF-8");
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
		}

		// Decode the nonce if base64encoded
		if (nonceBase64Encoded) {
			nonce = Base64.getDecoder().decode(nonceB64);
		} else {
			try {
				nonce = nonceB64.getBytes("UTF-8");
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
		}

		try {
			timeByte = timestamp.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		// Calculate the password digest from the nonce, timestamp and password
		result.update(nonce);
		result.update(timeByte);
		result.update(passwd);
		passwdDigest = new String(Base64.getEncoder().encode(result.digest()));
		return passwdDigest;
	}

	/**
	 * Calculate a random nonce
	 * 
	 * @param nonceBase64Encoded Is the nonce base64 encoded?
	 * @param nonceSize          Size of the nonce needed
	 * @return nonce
	 */
	public static String generate_nonce(boolean nonceBase64Encoded, int nonceSize) {
		String nonce = "";
		String possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
		for (int i = 0; i < nonceSize; i++) {
			nonce = nonce + possible.charAt((int) Math.floor(Math.random() * possible.length()));
		}
		// Base64 encode the nonce if needed
		if (nonceBase64Encoded) {
			try {
				nonce = new String(Base64.getEncoder().encode(nonce.getBytes("UTF-8")));
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
		}
		return nonce;
	}

	/**
	 * Return the timestamp fo the calculation of the token
	 * 
	 * @return timestamp
	 */
	public static String generate_created() {
		SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
		Date date = new Date();
		formatter.setTimeZone(TimeZone.getTimeZone("Berlin"));
		return formatter.format(date);
	}

	/**
	 * Return a random UUID
	 * 
	 * @return uuid
	 */
	public String getMessageId() {
		UUID uuid = UUID.randomUUID();
		return uuid.toString();
	}

	/**
	 * Calculate the password digest from the nonce, timestamp and password
	 * 
	 * @param password           the password
	 * @param nonceBase64Encoded Is the nonce base64 encoded?
	 * @param nonceSize          Size of the nonce needed
	 * @param pwdNeedHashing     Should the password be hashed?
	 * @param hashing            The hashing method
	 * @return res[timestamp, nonce, passwordDigest, UUID]
	 */
	public String[] getWSSecurity(String password, boolean nonceBase64Encoded, int nonceSize, boolean pwdNeedHashing,
			String hashing) {
		String[] res = new String[4];
		res[0] = generate_created();
		res[1] = generate_nonce(nonceBase64Encoded, nonceSize);
		res[2] = password_digest(res[1], res[0], password, nonceBase64Encoded, pwdNeedHashing, hashing);
		res[3] = getMessageId();
		logger.debug(res[0]);
		logger.debug(res[1]);
		logger.debug(res[2]);
		logger.debug(res[3]);
		return res;
	}
}
