import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class test {
	
	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		
		int AES_KEY_SIZE = 128;
		SecretKey AESKey = AES.keyGeneration(AES_KEY_SIZE);
		
		String keywords = Data.keywordsGenerate(1)[0];
		
		
		int[] fileNum = {100, 1000, 10000, 100000, 1000000};
		
		
		for(int i = 0; i < fileNum.length; i++) {
			
			int idLength = (int) Math.ceil(Math.log(fileNum[i])*1.0/Math.log(2));
			
			
			double t2 = System.currentTimeMillis();
			
			String IDs = "";
			for(int j = 0; j < fileNum[i]; j++) {
				
				String dumID = util.randomID(idLength);
				IDs = IDs + dumID;
			}
			
			String k_w = keywords + String.format("%0"+(AES_KEY_SIZE - keywords.length() - 5) +"d", 0) + 
					String.format("%04d", 0);
			
			byte[] addr = AES.Encrytor(k_w + "0", AESKey);
			byte[] seed = AES.Encrytor(k_w + "1", AESKey);
			
			BigInteger value = new BigInteger(seed);
			
			value = value.xor(new BigInteger(IDs, 2));
			
			System.out.println("fileNum:" + fileNum[i] + ";our scheme:" + (System.currentTimeMillis() - t2));
			
			
			double t1 = System.currentTimeMillis();
			for(int j = 0; j < fileNum[i]; j++) {
				
				k_w = keywords + String.format("%0"+(AES_KEY_SIZE - keywords.length() - 5) +"d", 0) + 
						String.format("%04d", j);
				
				addr = AES.Encrytor(k_w + "0", AESKey);
				
				value = new BigInteger(AES.Encrytor(k_w + "1", AESKey));
				
				String dumID = util.randomID(idLength);
				
				dumID = dumID + String.valueOf(1);
				
				value = value.xor(new BigInteger(dumID, 2));
			}
			
			System.out.println("fileNum:" + fileNum[i] + ";Mitra:" + (System.currentTimeMillis() - t1));
			
			 
		}

		
		
		
		
		
	}

}
