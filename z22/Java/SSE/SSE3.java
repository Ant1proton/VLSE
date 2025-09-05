import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BinaryOperator;

import javax.crypto.BadPaddingException;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class SSE3 {
	
	
	public String[] keywords;
	public int fileNum;
	public int idLength;
	public Map<String, Integer> idNum = new HashMap<String, Integer>();
	public int AES_KEY_SIZE;
	
	
	private SecretKey AESKey;
	private Map<String, Integer> FileCnt = new HashMap<String, Integer>();
	private List<String> randomKeywords = new ArrayList<String>();
	
	
	public SSE3(String[] keywords, int idLength, int fileNum, int AES_KEY_SIZE, SecretKey AESKey) {
		
		this.keywords = keywords;
		this.idLength = idLength;
		this.fileNum = fileNum;
		this.AES_KEY_SIZE = AES_KEY_SIZE;
		this.AESKey = AESKey;
	}

	public Map<String, byte[]> setup() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		
		Map<String, byte[]> DictW = new HashMap<String, byte[]>();		
		
		for(int i = 0; i < keywords.length; i++) {
			
			// Initialize the map FileCnt
			FileCnt.put(keywords[i], 0);
			idNum.put(keywords[i], 0);
		}
		
		return DictW;
		
	}
	
	public List<String> C2SRequest(String requestKeyword, int k) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		
		randomKeywords = util.randomKeywords(keywords, requestKeyword, k);
		
		List<String> locList = new ArrayList<String>();
		
		for(int i = 0; i < k; i++) {
			
			String k_w = randomKeywords.get(i) + String.format("%0"+(AES_KEY_SIZE-randomKeywords.get(i).length()-5) +"d", 0) + 
					String.format("%04d", FileCnt.get(randomKeywords.get(i)));
			
			byte[] addr = AES.Encrytor(k_w + "0", AESKey);	
			locList.add(Arrays.toString(addr));			
		}
		
		return locList;
	}
	
	public List<byte[]> S2CResponse(List<String> locList, Map<String, byte[]> DictW) {
				
		
		List<byte[]> ValList = new ArrayList<byte[]>();
		for(int i = 0; i < locList.size(); i++) {
			String key = locList.get(i);
			ValList.add(DictW.get(key));
		}
		
		return ValList;
	}
	
	
	public Map<String, byte[]> C2SReencrypt(String[] IDList, Map<String, byte[]> DictW) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		
		
		for(int i = 0; i < randomKeywords.size(); i++) {			
			
			
			String keyword = randomKeywords.get(i);
			int keywordLength = keyword.length();
			
			FileCnt.put(keyword, FileCnt.get(keyword) + 1);
			
			String k_w = keyword + String.format("%0"+(AES_KEY_SIZE- keywordLength -5) +"d", 0) + 
					String.format("%04d", FileCnt.get(keyword));
			
			byte[] addr = AES.Encrytor(k_w + "0", AESKey);
			byte[] value = AES.Encrytor(k_w + "1", AESKey);
			
			SecureRandom secureRandom = new SecureRandom(value);
			
			if(IDList[i] != null && IDList[i].compareTo("") != 0) {
				
				// the identities in byte form
				byte[] byteID = util.binStrToByteArr(IDList[i]);
				
//				System.out.println("encrypt byteIDs:" + Arrays.toString(byteID));
				
				// generate the key for PRG
				byte[] xor_key = new byte[byteID.length];
				secureRandom.nextBytes(xor_key);
				
//				System.out.println("encrypt xor_key:" + Arrays.toString(xor_key));
								
				int dummyByteLength = (int) Math.ceil(fileNum*idLength*1.0/8) - byteID.length;
				
				byte[] dummyByte = new byte[dummyByteLength];
				secureRandom.nextBytes(dummyByte);
				
				byte[] cipher = new byte[dummyByteLength + byteID.length];
				
				for(int j = 0; j < byteID.length; j++) {
					cipher[j] = (byte) (byteID[j] ^ xor_key[j]);
				}
				
//				System.out.println("encrypt cipher" + Arrays.toString(Arrays.copyOf(cipher, 3)));
				
				
				System.arraycopy(dummyByte, 0, cipher, byteID.length, dummyByte.length);
				
				DictW.put(Arrays.toString(addr), cipher);
				
			} else {
				
				int cipherLength = (int) Math.ceil(fileNum*idLength*1.0/8);
				byte[] cipher = new byte[cipherLength];
				secureRandom.nextBytes(cipher);
				DictW.put(Arrays.toString(addr), cipher);
				
			}
		}
		
		return DictW;
	}
	
	public Map<String, byte[]> searchProcess(String searchKeyword, int k, Map<String, byte[]> DictW) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		
		List<String> locList = C2SRequest(searchKeyword, k);
		List<byte[]> ValList = S2CResponse(locList, DictW);
	
		String[] IDList = new String[ValList.size()];
		for(int i = 0; i < randomKeywords.size(); i++) {
			
			String keyword = randomKeywords.get(i);
			int keywordLength = keyword.length();
			
			String strIDs = "";
			if(idNum.get(keyword) > 0 && ValList.get(i) != null) { // 添加ValList.get(i)不为null的检查
				
				String k_w = keyword + String.format("%0"+(AES_KEY_SIZE - keyword.length()-5) +"d", 0) + 
						String.format("%04d", FileCnt.get(keyword));
				
				byte[] value = AES.Encrytor(k_w + "1", AESKey);
				
				SecureRandom secureRandom = new SecureRandom(value);
				
				int IDsTrueLength = idNum.get(keyword)*idLength;
				int IDsByteLength = (int) Math.ceil(IDsTrueLength*1.0/8);
				
				// 确保IDsByteLength小于等于ValList.get(i).length
				if (ValList.get(i).length < IDsByteLength) {
					IDsByteLength = ValList.get(i).length;
				}
				
				// generate the key for PRG
				byte[] xor_key = new byte[IDsByteLength];
				secureRandom.nextBytes(xor_key);
				
				byte[] cipher1 = Arrays.copyOfRange(ValList.get(i), 0, IDsByteLength);
				
				byte[] byteIDs = new byte[cipher1.length];
				
				for(int j = 0; j < byteIDs.length; j++) {
					byteIDs[j] = (byte) (cipher1[j] ^ xor_key[j]);
				}
				
				strIDs = util.byteArrToBinStr(byteIDs);
				// 确保不会超出字符串长度
				if (strIDs.length() > IDsTrueLength) {
					strIDs = strIDs.substring(0, IDsTrueLength);
				}
			}
			
			IDList[i] = strIDs;		
			
		}
	
		DictW = C2SReencrypt(IDList, DictW);
		return DictW;
	}
	
	public Map<String, byte[]> updateProcess(String updateKeyword, int k, String updateID, int op, Map<String, byte[]> DictW) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

		List<String> locList = C2SRequest(updateKeyword, k);
		List<byte[]> ValList = S2CResponse(locList, DictW);

		
		String[] IDList = new String[ValList.size()];
		
		for(int i = 0; i < randomKeywords.size(); i++) {
			
			String keyword = randomKeywords.get(i);
			int keywordLength = keyword.length();
			
			String strIDs = "";
			
			if(idNum.get(keyword) > 0 && ValList.get(i) != null) { // 添加ValList.get(i)不为null的检查
				
				String k_w = keyword + String.format("%0"+(AES_KEY_SIZE - keyword.length()-5) +"d", 0) + 
						String.format("%04d", FileCnt.get(keyword));
				
				byte[] value = AES.Encrytor(k_w + "1", AESKey);
				
				SecureRandom secureRandom = new SecureRandom(value);
				
				int IDsTrueLength = idNum.get(keyword)*idLength;
				int IDsByteLength = (int) Math.ceil(IDsTrueLength*1.0/8);
				
				// 确保IDsByteLength小于等于ValList.get(i).length
				if (ValList.get(i).length < IDsByteLength) {
					IDsByteLength = ValList.get(i).length;
				}
				
				// generate the key for PRG
				byte[] xor_key = new byte[IDsByteLength];
				secureRandom.nextBytes(xor_key);
				
				byte[] cipher1 = Arrays.copyOfRange(ValList.get(i), 0, IDsByteLength);
				
				byte[] byteIDs = new byte[cipher1.length];
				
				for(int j = 0; j < byteIDs.length; j++) {
					byteIDs[j] = (byte) (cipher1[j] ^ xor_key[j]);
				}
				
				strIDs = util.byteArrToBinStr(byteIDs);
				// 确保不会超出字符串长度
				if (strIDs.length() > IDsTrueLength) {
					strIDs = strIDs.substring(0, IDsTrueLength);
				}
			}
			
			
			StringBuffer strBuffer = new StringBuffer();
			strBuffer.append(strIDs);
			
			int maxNum = idNum.get(updateKeyword);
			
			if(keyword.compareTo(updateKeyword) == 0) {
				
				if(op == 0 && maxNum > 0 && strIDs.length() > 0) {
					
					for(int j = 0; j < maxNum; j++) {
						// 确保索引不会超出字符串范围
						if (j*idLength < strIDs.length() && (j+1)*idLength <= strIDs.length()) {
							// 使用equals而不是==来比较字符串
							if(strIDs.substring(j*idLength, (j+1)*idLength).equals(updateID)) {
								// 确保不会超出字符串范围
								if (j*idLength < strBuffer.length() && (j+1)*idLength <= strBuffer.length()) {
									strBuffer.delete(j*idLength, (j+1)*idLength);
									break;
								}
							}
						}
					}
					
					idNum.put(updateKeyword, Math.max(0, idNum.get(updateKeyword) - 1));
					
				} else if(op == 1) {
					
					strBuffer.append(updateID);
					idNum.put(updateKeyword, idNum.get(updateKeyword) + 1);					
				}
			}
			
			strIDs = new String(strBuffer);
			IDList[i] = strIDs;	
			
//			System.out.println("updated strIDs:" + strIDs);
			
			
		}
		
		
		DictW = C2SReencrypt(IDList, DictW);
		return DictW;
		
	}
	

}