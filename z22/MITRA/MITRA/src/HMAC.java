import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class HMAC {

	private static final String MAC_NAME = "HmacSHA1";
	private static final String ENCODING = "UTF-8";

	public static byte[] HmacSHA1Encrypt(String encryptText, String encryptKey) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
		
		byte[] data=encryptKey.getBytes(ENCODING);
		SecretKey secretKey = new SecretKeySpec(data, MAC_NAME); 
		Mac mac = Mac.getInstance(MAC_NAME); 
		mac.init(secretKey);
		byte[] text = encryptText.getBytes(ENCODING); 
		return mac.doFinal(text); 
	}
	
	
	public static void main(String[] args) throws InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException {
		
		byte[] a = HmacSHA1Encrypt("1234" + "0", "345");
		byte[] b = HmacSHA1Encrypt("1234" + "1", "345");
		
		System.out.println(Arrays.toString(a));
		System.out.println(Arrays.toString(b));
		
		System.out.println(a.length);
		
	}

}
