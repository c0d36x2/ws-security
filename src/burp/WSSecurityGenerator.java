package burp;

import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import java.util.UUID;

import org.apache.ws.security.WSSecurityException;

import org.apache.ws.security.util.Base64;

public class WSSecurityGenerator
{
	private Logger logger;
    
	public WSSecurityGenerator(IBurpExtenderCallbacks callbacks){
        this.logger = new Logger(new PrintWriter(callbacks.getStdout(), true));
        Logger.setLogLevel(Logger.INFO);
    }
	
	public static String password_digest(String nonceB64, String timestamp, String pwd){
		String passwdDigest = null;
		MessageDigest shaPwd = null;
		MessageDigest result = null;
		try {
			shaPwd = MessageDigest.getInstance("SHA-1");
			result = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		byte[] nonce = null;
		try {
			nonce = Base64.decode(nonceB64);
		} catch (WSSecurityException e) {
			e.printStackTrace();
		}
		
		byte[] timeByte = null;
		try {
			shaPwd.update(pwd.getBytes("UTF-8"));
			timeByte = timestamp.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		
		result.update(nonce);
		result.update(timeByte);
		result.update(shaPwd.digest());
		byte[] mdbytes = shaPwd.digest();
		
		StringBuilder sb = new StringBuilder();
		for (byte d : mdbytes) {
			sb.append(String.format("%02x", new Object[] { Byte.valueOf(d) }));
		} 
		passwdDigest = new String(Base64.encode(result.digest()));
		return passwdDigest;
	}
	  
	public static String generate_nonce(boolean nonceBase64Encoded) {
		String nonce = "";
		String possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
		int len = 16;
		for (int i = 0; i < len; i++)
		{
			nonce = nonce + possible.charAt((int)Math.floor(Math.random() * possible.length()));
		}
		if (nonceBase64Encoded) {
			nonce = Base64.encode(nonce.getBytes());
		}
		return nonce;
	}
	  
	public static String generate_created() {
		SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
		Date date = new Date();
		formatter.setTimeZone(TimeZone.getTimeZone("Berlin"));	
		return formatter.format(date);
	}

	public String getMessageId() {
		UUID uuid = UUID.randomUUID();
		return uuid.toString();
	}
	
	public String[] getWSSecurity(String password, boolean nonceBase64Encoded) {
		String[] res = new String[4];
 		res[0] = generate_created();
         res[1] = generate_nonce(nonceBase64Encoded);
         res[2] = password_digest(res[1],res[0], password);
         res[3] = getMessageId();
         logger.debug(res[0]);
         logger.debug(res[1]);
         logger.debug(res[2]);
         logger.debug(res[3]);
         return res;
	}
}
 
