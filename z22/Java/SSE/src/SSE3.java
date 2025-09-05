import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class SSE3 {

    public String[] keywords;
    public int fileNum;
    public int idLength;
    public Map<String, Integer> idNum = new HashMap<>();
    public int AES_KEY_SIZE;

    private SecretKey AESKey;
    private Map<String, Integer> FileCnt = new HashMap<>();
    private List<String> randomKeywords = new ArrayList<>();
    private Map<String, String> latestAddrMap = new HashMap<>(); // 新增：记录每个关键词最新的密文地址

    public SSE3(String[] keywords, int idLength, int fileNum, int AES_KEY_SIZE, SecretKey AESKey) {
        this.keywords = keywords;
        this.idLength = idLength;
        this.fileNum = fileNum;
        this.AES_KEY_SIZE = AES_KEY_SIZE;
        this.AESKey = AESKey;
    }

    public Map<String, byte[]> setup() {
        Map<String, byte[]> DictW = new HashMap<>();
        for (String keyword : keywords) {
            FileCnt.put(keyword, 0);
            idNum.put(keyword, 0);
        }
        return DictW;
    }

    public List<String> C2SRequest(String requestKeyword, int k) throws Exception {
        randomKeywords = util.randomKeywords(keywords, requestKeyword, k);
        List<String> locList = new ArrayList<>();
        for (String keyword : randomKeywords) {
            String k_w = keyword + String.format("%0" + (AES_KEY_SIZE - keyword.length() - 5) + "d", 0) +
                    String.format("%04d", FileCnt.get(keyword));
            byte[] addr = AES.Encrytor(k_w + "0", AESKey);
            locList.add(Arrays.toString(addr));
        }
        return locList;
    }

    public List<byte[]> S2CResponse(List<String> locList, Map<String, byte[]> DictW) {
        List<byte[]> ValList = new ArrayList<>();
        for (String key : locList) {
            ValList.add(DictW.get(key));
        }
        return ValList;
    }

    public Map<String, byte[]> C2SReencrypt(String[] IDList, Map<String, byte[]> DictW) throws Exception {
        for (int i = 0; i < randomKeywords.size(); i++) {
            String keyword = randomKeywords.get(i);
            int keywordLength = keyword.length();

            FileCnt.put(keyword, FileCnt.get(keyword) + 1);
            String k_w = keyword + String.format("%0" + (AES_KEY_SIZE - keywordLength - 5) + "d", 0) +
                    String.format("%04d", FileCnt.get(keyword));
            byte[] addr = AES.Encrytor(k_w + "0", AESKey);
            byte[] value = AES.Encrytor(k_w + "1", AESKey);
            String addrStr = Arrays.toString(addr);

            SecureRandom secureRandom = new SecureRandom(value);
            byte[] cipher;

            if (IDList[i] != null && !IDList[i].isEmpty()) {
                byte[] byteID = util.binStrToByteArr(IDList[i]);
                byte[] xor_key = new byte[byteID.length];
                secureRandom.nextBytes(xor_key);
                int dummyByteLength = (int) Math.ceil(fileNum * idLength / 8.0) - byteID.length;
                byte[] dummyByte = new byte[dummyByteLength];
                secureRandom.nextBytes(dummyByte);
                cipher = new byte[dummyByteLength + byteID.length];

                for (int j = 0; j < byteID.length; j++) {
                    cipher[j] = (byte) (byteID[j] ^ xor_key[j]);
                }
                System.arraycopy(dummyByte, 0, cipher, byteID.length, dummyByte.length);
            } else {
                int cipherLength = (int) Math.ceil(fileNum * idLength / 8.0);
                cipher = new byte[cipherLength];
                secureRandom.nextBytes(cipher);
            }

            if (latestAddrMap.containsKey(keyword)) {
                DictW.remove(latestAddrMap.get(keyword));
            }

            DictW.put(addrStr, cipher);
            latestAddrMap.put(keyword, addrStr);
        }
        return DictW;
    }

    public Map<String, byte[]> searchProcess(String searchKeyword, int k, Map<String, byte[]> DictW) throws Exception {
        List<String> locList = C2SRequest(searchKeyword, k);
        List<byte[]> ValList = S2CResponse(locList, DictW);

        String[] IDList = new String[ValList.size()];
        for (int i = 0; i < randomKeywords.size(); i++) {
            String keyword = randomKeywords.get(i);
            String strIDs = "";
            if (idNum.get(keyword) > 0 && ValList.get(i) != null) {
                String k_w = keyword + String.format("%0" + (AES_KEY_SIZE - keyword.length() - 5) + "d", 0) +
                        String.format("%04d", FileCnt.get(keyword));
                byte[] value = AES.Encrytor(k_w + "1", AESKey);
                SecureRandom secureRandom = new SecureRandom(value);
                int IDsTrueLength = idNum.get(keyword) * idLength;
                int IDsByteLength = (int) Math.ceil(IDsTrueLength / 8.0);
                if (ValList.get(i).length < IDsByteLength) {
                    IDsByteLength = ValList.get(i).length;
                }
                byte[] xor_key = new byte[IDsByteLength];
                secureRandom.nextBytes(xor_key);
                byte[] cipher1 = Arrays.copyOfRange(ValList.get(i), 0, IDsByteLength);
                byte[] byteIDs = new byte[IDsByteLength];
                for (int j = 0; j < IDsByteLength; j++) {
                    byteIDs[j] = (byte) (cipher1[j] ^ xor_key[j]);
                }
                strIDs = util.byteArrToBinStr(byteIDs);
                if (strIDs.length() > IDsTrueLength) {
                    strIDs = strIDs.substring(0, IDsTrueLength);
                }
            }
            IDList[i] = strIDs;
        }
        return C2SReencrypt(IDList, DictW);
    }

    public Map<String, byte[]> updateProcess(String updateKeyword, int k, String updateID, int op, Map<String, byte[]> DictW) throws Exception {
        List<String> locList = C2SRequest(updateKeyword, k);
        List<byte[]> ValList = S2CResponse(locList, DictW);
        String[] IDList = new String[ValList.size()];

        for (int i = 0; i < randomKeywords.size(); i++) {
            String keyword = randomKeywords.get(i);
            String strIDs = "";
            if (idNum.get(keyword) > 0 && ValList.get(i) != null) {
                String k_w = keyword + String.format("%0" + (AES_KEY_SIZE - keyword.length() - 5) + "d", 0) +
                        String.format("%04d", FileCnt.get(keyword));
                byte[] value = AES.Encrytor(k_w + "1", AESKey);
                SecureRandom secureRandom = new SecureRandom(value);
                int IDsTrueLength = idNum.get(keyword) * idLength;
                int IDsByteLength = (int) Math.ceil(IDsTrueLength / 8.0);
                if (ValList.get(i).length < IDsByteLength) {
                    IDsByteLength = ValList.get(i).length;
                }
                byte[] xor_key = new byte[IDsByteLength];
                secureRandom.nextBytes(xor_key);
                byte[] cipher1 = Arrays.copyOfRange(ValList.get(i), 0, IDsByteLength);
                byte[] byteIDs = new byte[IDsByteLength];
                for (int j = 0; j < IDsByteLength; j++) {
                    byteIDs[j] = (byte) (cipher1[j] ^ xor_key[j]);
                }
                strIDs = util.byteArrToBinStr(byteIDs);
                if (strIDs.length() > IDsTrueLength) {
                    strIDs = strIDs.substring(0, IDsTrueLength);
                }
            }
            StringBuilder strBuffer = new StringBuilder(strIDs);
            int maxNum = idNum.get(updateKeyword);
            if (keyword.equals(updateKeyword)) {
                if (op == 0 && maxNum > 0 && strIDs.length() > 0) {
                    for (int j = 0; j < maxNum; j++) {
                        int start = j * idLength;
                        int end = (j + 1) * idLength;
                        if (end <= strIDs.length() && strIDs.substring(start, end).equals(updateID)) {
                            strBuffer.delete(start, end);
                            break;
                        }
                    }
                    idNum.put(updateKeyword, Math.max(0, idNum.get(updateKeyword) - 1));
                } else if (op == 1) {
                    strBuffer.append(updateID);
                    idNum.put(updateKeyword, idNum.get(updateKeyword) + 1);
                }
            }
            IDList[i] = strBuffer.toString();
        }
        return C2SReencrypt(IDList, DictW);
    }

    public Map<String, Integer> getFileCnt() {
        return this.FileCnt;
    }
}
