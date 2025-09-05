import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

public class util {

	public static String randomID(int num) {
		
		String randomVal = "";
		for(int i = 0; i < num; i++) {
			int rd=Math.random()>0.5?1:0;
			randomVal = randomVal + String.valueOf(rd);
		}
		return randomVal;
	}
	
	public static List<String> randomKeywords(String[] keywords, String searchKeyword, int k) {
		
		Set<String> randomKeywords = new HashSet<String>();
		
		randomKeywords.add(searchKeyword);
		while(randomKeywords.size() < k) {
			randomKeywords.add(keywords[new Random().nextInt(keywords.length)]);
		}
		
		return new ArrayList<String>(randomKeywords);
	}
	
	public static byte[] binStrToByteArr(String binStr) {
		
		int n = (int) Math.ceil(binStr.length()*1.0/8);
		byte[] b = new byte[n];
		
		int i;
		for(i = 0; i < n - 1; i++) {
			
			b[i] = Long.valueOf(binStr.substring(i*8, (i+1)*8), 2).byteValue();
		}
		
		
		String cover = Integer.toBinaryString(1 << 8).substring(1);
		String s = binStr.substring(i*8, binStr.length());
		s = s + cover.substring(s.length());
		
		b[n - 1] = Long.valueOf(s, 2).byteValue();
	    
	    return b;
	}	
	

	public static byte[] intToByteArray(int a) {
	    return new byte[] {
	        (byte) ((a >> 24) & 0xFF),
	        (byte) ((a >> 16) & 0xFF),   
	        (byte) ((a >> 8) & 0xFF),   
	        (byte) (a & 0xFF)
	    };
	}
	
	public static String byteArrToBinStr(byte[] b) {
		
//		String base64 = Base64.getEncoder().encodeToString(b);
//		System.out.println(base64); 
		
		
		String cover = Integer.toBinaryString(1 << 8).substring(1);
	    StringBuffer result = new StringBuffer();
	    for (int i = 0; i < b.length; i++) {

	    	String s = Integer.toBinaryString(b[i] & 0xff);
		    result.append(s.length() < 8 ? cover.substring(s.length()) + s : s);
	    }
	    
	    return result.toString();
	}
	
	public static void main(String[] args) {
		
//		byte a = util.intToByteArray(256);
//		System.out.println(Arrays.toString(a));
		
//		byte a = Integer.valueOf("0",2).byteValue();
//		
//		System.out.println(a);
//		
		
		String a = "0010";
		byte[] b = a.getBytes();
		
		a = new String(b);
		
		System.out.println(a);
		
	}
	    
	    
	   

	
		
}
