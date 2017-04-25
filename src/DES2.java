import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Encoder;

import javax.xml.bind.DatatypeConverter;

/**@author Sali Ben Mocha, Shay Hood**/

public class DES2{
	
	/*
	 * In this table we use to mix the bits in the message. 
	 * After mixing the message, we divide it into two parts - left and right according to the table. 
	 * Until the fourth line will be left and all the other lines will be the right part of the message.
	 * */
	
	 public static byte[] IP = { 
		        58, 50, 42, 34, 26, 18, 10, 2,
		        60, 52, 44, 36, 28, 20, 12, 4,
		        62, 54, 46, 38, 30, 22, 14, 6,
		        64, 56, 48, 40, 32, 24, 16, 8,
		        57, 49, 41, 33, 25, 17, 9,  1,
		        59, 51, 43, 35, 27, 19, 11, 3,
		        61, 53, 45, 37, 29, 21, 13, 5,
		        63, 55, 47, 39, 31, 23, 15, 7
		    };
	 
	 /*This table uses the final part of the encryption - 
	  * to reverse the bits, this essentially cancels the operation in the IP table
	  * */
	 
	  private static byte[] IPminus1 = {
		        40, 8, 48, 16, 56, 24, 64, 32,
		        39, 7, 47, 15, 55, 23, 63, 31,
		        38, 6, 46, 14, 54, 22, 62, 30,
		        37, 5, 45, 13, 53, 21, 61, 29,
		        36, 4, 44, 12, 52, 20, 60, 28,
		        35, 3, 43, 11, 51, 19, 59, 27,
		        34, 2, 42, 10, 50, 18, 58, 26,
		        33, 1, 41, 9, 49, 17, 57, 25
		    };
	
	  /*Using this table, you extend the input from a 32-bit array to a 48-bit array
		The 32 bits are actually the right or left side we received from the IP table.*/
	  
	  
	  private static byte[] E = {
		        32, 1,  2,  3,  4,  5,
		        4,  5,  6,  7,  8,  9,
		        8,  9,  10, 11, 12, 13,
		        12, 13, 14, 15, 16, 17,
		        16, 17, 18, 19, 20, 21,
		        20, 21, 22, 23, 24, 25,
		        24, 25, 26, 27, 28, 29,
		        28, 29, 30, 31, 32, 1
		    };
		    
	  
	  /*The P (Permutation) box is another static value box that converts the
	   *  input at the end of each round while maintaining its size - 32 bits.*/
	  
	    private static byte[] P = {
	            16, 7,  20, 21,
	            29, 12, 28, 17,
	            1,  15, 23, 26,
	            5,  18, 31, 10,
	            2,  8,  24, 14,
	            32, 27, 3,  9,
	            19, 13, 30, 6,
	            22, 11, 4,  25
	        };
	    
	    /*
	     * Substitution Boxes are part from the F(Feistel) function;
	     *They are perform bit substitutions according to this array - there are 8 tables at this array.  
	     * the value is splited into 6-bit sections, and each section is permuted
	     * into a different s box according to these eight tables. (One table for each section.)
	     */
	  private static byte[][] S = { {
	        14, 4,  13, 1,  2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0,  7,
	        0,  15, 7,  4,  14, 2,  13, 1,  10, 6,  12, 11, 9,  5,  3,  8,
	        4,  1,  14, 8,  13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5,  0,
	        15, 12, 8,  2,  4,  9,  1,  7,  5,  11, 3,  14, 10, 0,  6,  13
	    }, {
	        15, 1,  8,  14, 6,  11, 3,  4,  9,  7,  2,  13, 12, 0,  5,  10,
	        3,  13, 4,  7,  15, 2,  8,  14, 12, 0,  1,  10, 6,  9,  11, 5,
	        0,  14, 7,  11, 10, 4,  13, 1,  5,  8,  12, 6,  9,  3,  2,  15,
	        13, 8,  10, 1,  3,  15, 4,  2,  11, 6,  7,  12, 0,  5,  14, 9
	    }, {
	        10, 0,  9,  14, 6,  3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8,
	        13, 7,  0,  9,  3,  4,  6,  10, 2,  8,  5,  14, 12, 11, 15, 1,
	        13, 6,  4,  9,  8,  15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7,
	        1,  10, 13, 0,  6,  9,  8,  7,  4,  15, 14, 3,  11, 5,  2,  12
	    }, {
	        7,  13, 14, 3,  0,  6,  9,  10, 1,  2,  8,  5,  11, 12, 4,  15,
	        13, 8,  11, 5,  6,  15, 0,  3,  4,  7,  2,  12, 1,  10, 14, 9,
	        10, 6,  9,  0,  12, 11, 7,  13, 15, 1,  3,  14, 5,  2,  8,  4,
	        3,  15, 0,  6,  10, 1,  13, 8,  9,  4,  5,  11, 12, 7,  2,  14
	    }, {
	        2,  12, 4,  1,  7,  10, 11, 6,  8,  5,  3,  15, 13, 0,  14, 9,
	        14, 11, 2,  12, 4,  7,  13, 1,  5,  0,  15, 10, 3,  9,  8,  6,
	        4,  2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,  6,  3,  0,  14,
	        11, 8,  12, 7,  1,  14, 2,  13, 6,  15, 0,  9,  10, 4,  5,  3
	    }, {
	        12, 1,  10, 15, 9,  2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11,
	        10, 15, 4,  2,  7,  12, 9,  5,  6,  1,  13, 14, 0,  11, 3,  8,
	        9,  14, 15, 5,  2,  8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6,
	        4,  3,  2,  12, 9,  5,  15, 10, 11, 14, 1,  7,  6,  0,  8,  13
	    }, {
	        4,  11, 2,  14, 15, 0,  8,  13, 3,  12, 9,  7,  5,  10, 6,  1,
	        13, 0,  11, 7,  4,  9,  1,  10, 14, 3,  5,  12, 2,  15, 8,  6,
	        1,  4,  11, 13, 12, 3,  7,  14, 10, 15, 6,  8,  0,  5,  9,  2,
	        6,  11, 13, 8,  1,  4,  10, 7,  9,  5,  0,  15, 14, 2,  3,  12
	    }, {
	        13, 2,  8,  4,  6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7,
	        1,  15, 13, 8,  10, 3,  7,  4,  12, 5,  6,  11, 0,  14, 9,  2,
	        7,  11, 4,  1,  9,  12, 14, 2,  0,  6,  10, 13, 15, 3,  5,  8,
	        2,  1,  14, 7,  4,  10, 8,  13, 15, 12, 9,  0,  3,  5,  6,  11
	    } };
	  
	  /*This section refers to the encryption key.
	  The K key is extended to an array of 16 48-bit inputs.
	  In this table, users are used to copy the key bits K to two local C D variables of 28 bits each in the order in the table. The first two lines are for C and the last two lines are for D. (The bits are counted from 0).
	  Because only 56 bits are copied from the 64,
	   we say that we actually use only 56 bits of the encryption key. */
	  
	  private static byte[] PC1 = {
		        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
		        10, 2,  59, 51, 43, 35, 27,19, 11, 3,  60, 52, 44, 36,
		        63, 55, 47, 39, 31, 23, 15, 7,  62, 54, 46, 38, 30, 22,
		        14, 6,  61, 53, 45, 37, 29,21, 13, 5,  28, 20, 12, 4
		    };
	  
	  /*using this table,PC2  we find the key to the current round - with which 48 bits are selected for the key.  */
	  
	  private static final byte[] PC2 = {
		        14, 17, 11, 24, 1,  5,
		        3,  28, 15, 6,  21, 10,
		        23, 19, 12, 4,  26, 8,
		        16, 7,  27, 20, 13, 2,
		        41, 52, 31, 37, 47, 55,
		        30, 40, 51, 45, 33, 48,
		        44, 49, 39, 56, 34, 53,
		        46, 42, 50, 36, 29, 32
		    };
	  
	  
	  /*v is an helpful array
	   * In places 1 2 9 16 we will update value 1 while in all other places we will update 2 */
	  
	        	    
	    /**
	     * IP function : this function get the text that we want to encode 
	     * and return it after we confused its bits by IP table; 
	     * @param input
	     * @return our input after mixing his bits 
	     */
	    private static long IP(long input)  { 
	    	return permute(IP, 64, input);                 
	    	} // 64-bit output
	    
	    /**
	     * IPreverse function : This function receives the input after encryption and performs the blinking operation to the IP function, 
	     * which returns the input to its original order.
	     * @param encrypted input
	     * @return our encrypted input after canceling the  mixing on his bits 
	     */
	    private static long IPreverse(long input)  { 
	    	return permute(IPminus1, 64, input);                 
	    	} // 64-bit output
	    
	    /**
	     * E function  change the input from 32 bits to 48 bits 
	     * @param the R(right) side of the input
	     * @return  48 bits of input
	     */
	    private static long E(int input)    { 
	    	return permute(E, 32, input&0xFFFFFFFFL);      
	    } // 48-bit output
	    
	    /**
	     * P function change the input from 48 bits to 32 bits 
	     * @param the input after s function
	     * @return 32 bits of input 
	     */
	    private static int  P(int input)    { 
	    	return (int)permute(P, 32, input&0xFFFFFFFFL); 
	    } // 32-bit output
	    
	    /**
	     * pc1 is a function for the key.  The K key is extended to an array of 16 48-bit inputs.
	     * it change the key from 64 bits to 56 bits
	     * @param the key
	     * @return  56 bits from the key after change it 
	     */
	    private static long PC1(long key) { 
	    	return permute(PC1, 64, key);                
	    } // 56-bit output
	    
	    /**
	     * pc2 change the key for the current round
	     * @param the current key
	     * @return  an input of the key
	     */
	    private static long PC2(long key) { 
	    	return permute(PC2, 56, key);                
	    } // 48-bit output
	    

	    /**
	     * tthis function get any input and some array, and change the input  in accordance to the array. each array contains index for the bits -
	     * so the output of the text we sent is arranged according to the indexes of the array we send to this function 
	     * @param some input
	     * @return  permutation of the input
	     */
	    private static long permute(byte[] array, int inputLength, long input) {

	    	  long output = 0;
	    	  int size = array.length;
	    	  int i=0,inputPlace;
	    	  
	    	  while(i<size)
	    	  {
	    		  inputPlace = inputLength - array[i];
	    		  output = (output<<1) | (input>>inputPlace & 0x01); //shift, 0x01 on ascii is 1
	              i++;
	    	  }
	    	    
	          return output;
		}


	    /**
	     * 
	     * @param 6 bits of input (part of the chipher text), s box number - array index
	     * @return  s[row][col]
	     */
	    private static byte Sbox(int boxNumber, byte input) {
	    	
	    	input = (byte) (input&0x20 | ((input&0x01)<<4) | ((input&0x1E)>>1)); // 0x20 is 2,0x01 is 1 0x1E is 
	        return S[boxNumber-1][input];
	    }
	    
	    
	    
	    private static long getLongFromBytes(byte[] ba, int offset) { // change bytes to a long number
	        long l = 0;
	        for (int i=0; i<8; i++) {
	            byte value;
	            if ((offset+i) < ba.length) {
	                value = ba[offset+i];
	            } else {
	                value = 0;
	            }
	            l = l<<8 | (value & 0xFFL);
	        }
	        return l;
	    }
	    
	    private static void getBytesFromLong(byte[] ba, int offset, long l) {// change to bytes from long
	        for (int i=7; i>=0; i--) {
	            if ((offset+i) < ba.length) {
	                ba[offset+i] = (byte) (l & 0xFF);
	                l = l >> 8;
	            } else {
	                break;
	            }
	        }
	    }
	    
	    /**
	     * The Feistel function is the heart of DES.
	     */
	    private static int Ffunction(int r, /* 48 bits */ long subkey) {
	        // 1. expansion
	        long e = E(r);
	        // 2. key mixing
	        long x = e ^ subkey;
	        // 3. substitution
	        int dst = 0;
	        for (int i=0; i<8; i++) {
	            dst>>>=4;
	            int s = Sbox(8-i, (byte)(x&0x3F));
	            dst |= s << 28;
	            x>>=6;
	        }
	        // 4. permutation
	        return P(dst);
	    }
	    
	    
	    private static long[] createSubkeys( long key) {
	        long subkeys[] = new long[3];
	        
	        // perform the PC1 permutation
	        key = PC1(key);
	        
	        // split into 28-bit left and right (c and d) pairs.
	        int c = (int) (key>>28);
	        int d = (int) (key&0x0FFFFFFF);
	        long cd;
	        
	        //for the first key
            // rotate by 1 bit
	        c = ((c<<1) & 0x0FFFFFFF) | (c>>27);
            d = ((d<<1) & 0x0FFFFFFF) | (d>>27);	        
            cd = (c&0xFFFFFFFFL)<<28 | (d&0xFFFFFFFFL);
	        
            subkeys[0] = PC2(cd);
            
	        //for the second key
            // rotate by 1 bit
	        c = ((c<<1) & 0x0FFFFFFF) | (c>>27);
            d = ((d<<1) & 0x0FFFFFFF) | (d>>27);	        
            cd = (c&0xFFFFFFFFL)<<28 | (d&0xFFFFFFFFL);
	        
            subkeys[1] = PC2(cd);
            
            //for the third
            // rotate by 2 bits
            c = ((c<<2) & 0x0FFFFFFF) | (c>>26);
            d = ((d<<2) & 0x0FFFFFFF) | (d>>26);	       
            cd = (c&0xFFFFFFFFL)<<28 | (d&0xFFFFFFFFL);
	        
            subkeys[2] = PC2(cd);
            
	        return subkeys; 
	    }
	    

	    public static long encryptBlock(long msg,long key) {
	        
	    	long subkeys[] = createSubkeys(key); // only 3 on our case
	        long ip = IP(msg);
	        
	        // split the 32-bit value into 16-bit left and right halves.
	        int left = (int) (ip>>32);
	        int right = (int) (ip&0xFFFFFFFFL);
	        
	        // perform 16 rounds
	        for (int i=0; i<3; i++) {
	            int previous_l = left;
	            // the right half becomes the new left half.
	            left = right;
	            // the Ffunction function is applied to the old left half
	            // and the resulting value is stored in the right half.
	            right = previous_l ^ Ffunction(right, subkeys[i]); //^ xor in java
	        }
	        
	        
	     // reverse the two 32-bit segments (left to right; right to left)
	        long rl = (right&0xFFFFFFFFL)<<32 | (left&0xFFFFFFFFL);
	        
	        // apply the final permutation
	        long ciphertext = IPreverse(rl);
	        
	        // return the ciphertext
	        return ciphertext;
	    }
	    
	    
	    
	    public static void encryptBlock(byte[] message,int messageOffset,byte[] ciphertext,int ciphertextOffset, byte[] key) {
	            
	    		long msg = getLongFromBytes(message, messageOffset);
	            long k = getLongFromBytes(key, 0);
	            long ctext = encryptBlock(msg, k);
	            getBytesFromLong(ciphertext, ciphertextOffset, ctext);
	    }
	    
	    
	    public static byte[] encrypt(byte[] message, byte[] key) {
	        byte[] ciphertext = new byte[message.length];

	        // encrypt each 8-byte (64-bit) block of the message.
	        for (int i=0; i<message.length; i+=8) {
	            encryptBlock(message, i, ciphertext, i, key);
	        }
	        
	        return ciphertext;
	    }
	    
	    
	    public static byte[] encrypt(byte[] challenge, String password) {
	        return encrypt(challenge, passwordToKey(password));
	    }
	    
	    
	    private static byte[] passwordToKey(String password) {
	        byte[] pwbytes = password.getBytes();
	        byte[] key = new byte[8];
	        for (int i=0; i<8; i++) {
	            if (i < pwbytes.length) {
	                byte b = pwbytes[i];
	                // flip the byte
	                byte b2 = 0;
	                for (int j=0; j<8; j++) {
	                    b2<<=1;
	                    b2 |= (b&0x01);
	                    b>>>=1;
	                }
	                key[i] = b2;
	            } else {
	                key[i] = 0;
	            }
	        }
	        return key;
	    }
	    
	    /*
	    private static int charToNibble(char c) {
	        if (c>='0' && c<='9') {
	            return (c-'0');
	        } else if (c>='a' && c<='f') {
	            return (10+c-'a');
	        } else if (c>='A' && c<='F') {
	            return (10+c-'A');
	        } else {
	            return 0;
	        }
	    }
	    private static byte[] parseBytes(String s) {
	        s = s.replace(" ", "");
	        byte[] ba = new byte[s.length()/2];
	        if (s.length()%2 > 0) { s = s+'0'; }
	        for (int i=0; i<s.length(); i+=2) {
	            ba[i/2] = (byte) (charToNibble(s.charAt(i))<<4 | charToNibble(s.charAt(i+1)));
	        }
	        return ba;
	    }
	    private static String hex(byte[] bytes) {
	        StringBuilder sb = new StringBuilder();
	        for (int i=0; i<bytes.length; i++) {
	            sb.append(String.format("%02X ",bytes[i]));
	        }
	        return sb.toString();
	    }

	   
	    
	    /*
	    
	    public static boolean test(byte[] message, byte[] expected, String password) {
	        return test(message, expected, passwordToKey(password));
	    }
	     */
	    
		/*public static void main(String[] args) {
	        
			String message = "nonsense";
			String myKey = "abababan";
			
	        System.out.println("\tmessage:  "+message);
	        System.out.println("\tkey:      "+myKey);
	        byte[] received = encrypt(parseBytes(message), parseBytes(myKey));        
	        System.out.println("\treceived: "+DatatypeConverter.printHexBinary(received));
	         
	    }*/
	   
	    
	    private static int charToNibble(char c) {
	        if (c>='0' && c<='9') {
	            return (c-'0');
	        } else if (c>='a' && c<='f') {
	            return (10+c-'a');
	        } else if (c>='A' && c<='F') {
	            return (10+c-'A');
	        } else {
	            return 0;
	        }
	    }
	    private static byte[] parseBytes(String s) {
	        s = s.replace(" ", "");
	        byte[] ba = new byte[s.length()/2];
	        if (s.length()%2 > 0) { s = s+'0'; }
	        for (int i=0; i<s.length(); i+=2) {
	            ba[i/2] = (byte) (charToNibble(s.charAt(i))<<4 | charToNibble(s.charAt(i+1)));
	        }
	        return ba;
	    }
	    private static String hex(byte[] bytes) {
	        StringBuilder sb = new StringBuilder();
	        for (int i=0; i<bytes.length; i++) {
	            sb.append(String.format("%02X ",bytes[i]));
	        }
	        return sb.toString();
	    }

	    public static boolean test(byte[] message, byte[] expected, String password) {
	        return test(message, expected, passwordToKey(password));
	    }
	    
	    private static int testCount = 0;
	    public static boolean test(byte[] message, byte[] expected, byte[] key) {
	        System.out.println("Test #"+(++testCount)+":");
	        System.out.println("\tmessage:  "+hex(message));
	        System.out.println("\tkey:      "+hex(key));
	        System.out.println("\texpected: "+hex(expected));
	        byte[] received = encrypt(message, key);
	        System.out.println("\treceived: "+hex(received));
	        boolean result = Arrays.equals(expected, received);
	        System.out.println("\tverdict: "+(result?"PASS":"FAIL"));
	        return result;
	    }
	    
	    
	    public static String toHexadecimal(String text)
	    {
	        byte[] myBytes = null;
			try {
				myBytes = text.getBytes("UTF-8");
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

	        return DatatypeConverter.printHexBinary(myBytes);
	    }
	    

	    public static void main(String[] args) {

	        // These tests were derived from the password challenge-response
	        // conversations observed between a VNC client and server. 
	  
	    	
	        test(
	            parseBytes(toHexadecimal("Salli The not normalit")),
	            parseBytes("fa60 69b9 85fa 1cf7 0bea a041 9137 a6d3"),
	            "mypass"
	        		);
	        
	    }
}
 