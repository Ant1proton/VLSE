import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class test {
	
	public static void main(String[] args) {
		
		
		int[] k = {10,20,30};
		int[] FileNum = {100, 1000, 10000, 100000};
		for(int i = 0; i< k.length; i++) {
			for(int j = 0; j< FileNum.length; j++) 
				System.out.print(2*k[i]*(160+FileNum[j])/8 + ",");
			System.out.println();
		}
			
		
	}
	
}
