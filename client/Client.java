import java.net.*; 
import java.io.*; 
import javax.crypto.*;
import java.math.*;
import java.sql.Timestamp;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import java.nio.file.Files;
import javax.crypto.Cipher;
import java.util.Base64;
import java.util.Random;
import java.net.*;
import java.security.SignatureException;
import java.util.Formatter;
import javax.crypto.Mac;
import java.nio.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import java.io.DataOutputStream;
import javax.crypto.spec.SecretKeySpec;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;


public class Client 
{

	static String integrityCheck;
    private static Cipher encryptCipher;
	private static Cipher decryptCipher;
    private byte[] serverHelloMessage;
  //  private SecretKey key;
    private byte[] helloNonce;
    private byte[] askForCertNonce;
	private static Socket socket,socket1;
    private byte[] fileToSend;
  //  private static Key serverPublicKey;
	
	static long  P, G, x, a, y, b, ka, kb,fileSize;
	static long leftLimit = 1000000000000000L;
	static long rightLimit = 9999999999999999L;
	private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
	private static String key = "12345678910";
	private static final String IV = "ThisIsFirstPacket";
	static int packetsize=1024;
	static double nosofpackets;
	static byte[] cipher ;
	static byte[] prev ;
	static byte [] plaintext;
	
    public static void main (String [] args ) throws IOException,FileNotFoundException,Exception 
    {
	   
		System.out.println("Start"); 
	    int bytesRead;
	    int currentTot = 0; 
	
	   while(true)
       {
		socket = new Socket("localhost",6000);
	//	System.out.println("Connection made");
		key = String.valueOf(kb);
        System.out.println("\n1. Download\n2. Upload\n3. Receive certificate\n4. Generate key \n5. Quit\n6. List files on server \n7. List files on system");
        Scanner sc = new Scanner(System.in);
        int choice=sc.nextInt();
        OutputStream os = null;
        os= socket.getOutputStream();
        DataOutputStream dos = new DataOutputStream(os);
        dos.writeUTF(String.valueOf(choice));
		
		//1. download 2. upload 3. get certificate 4. get keys 5. exit
			switch(choice)
			{
				case 1:
					System.out.println("Enter file name you want to download: ");
					String fname = sc.next();
					
					OutputStream osf= socket.getOutputStream();
					DataOutputStream dosf = new DataOutputStream(osf);
					dosf.writeUTF(fname);
					
					FileOutputStream fos = new FileOutputStream(fname);
					BufferedOutputStream bos5 = new BufferedOutputStream(fos);
					InputStream is1 = socket.getInputStream();
					DataInputStream bis5 = new DataInputStream(is1);
					String temp = bis5.readUTF();
					fileSize = Long.valueOf(temp);
					double nosofpackets=Math.ceil(((int) fileSize)/packetsize);
					for(double i=0;i<nosofpackets+1;i++)
					{
						InputStream is5 = socket.getInputStream();
						byte[] mybytearray = new byte[packetsize];
						bytesRead = is5.read(mybytearray, 0,mybytearray.length );
						
						if(i == 0)
						{
							String b_i = calculateRFC2104HMAC(IV,key);
							plaintext = xoring(mybytearray,b_i.getBytes());
							prev = mybytearray;
						}
						else
						{
							String b_i = calculateRFC2104HMAC(new String(prev),key);
							plaintext = xoring(mybytearray,b_i.getBytes());
							prev = mybytearray;
							
							if(i == nosofpackets)
							{
								integrityCheck = calculateRFC2104HMAC(b_i,key);
							}
						}
						System.out.println("Packet:"+(i+1));
						bos5.write(plaintext, 0,plaintext.length);
					}
					
					System.out.println("File successfully downloaded");	
					
					System.out.println("Integrity check value received");
					InputStream is = socket.getInputStream();
					DataInputStream in = new DataInputStream(is);
					String integrityReceived = String.valueOf(in.readUTF());
					
					if(integrityReceived.equals(integrityCheck))
					{
						System.out.println("Integrity check: True");
					}
					else
					{
						System.out.println("Integrity check: False");
					}
					
					socket.close();
					bos5.close();
					
				break;
				
				case 2:
				
					System.out.println("Enter file name you want to upload: ");
					String fnamen = sc.next();
					
					OutputStream osfn= socket.getOutputStream();
					DataOutputStream dosfn = new DataOutputStream(osfn);
					dosfn.writeUTF(fnamen);
					
					File myFile = new File(fnamen);
					fileSize = myFile.length();
					nosofpackets=Math.ceil(((int) myFile.length())/packetsize);
					BufferedInputStream bis = new BufferedInputStream(new FileInputStream(myFile));
					OutputStream os1 = socket.getOutputStream();
					DataOutputStream bos = new DataOutputStream(os1);
					bos.writeUTF(String.valueOf(fileSize));
					
					for(double i=0;i<nosofpackets+1;i++) {
						
						byte[] mybytearray = new byte[packetsize];
						bis.read(mybytearray, 0, mybytearray.length);
						System.out.println("Packet:"+(i+1));
						
						if(i==0)
						{
							String b_i = calculateRFC2104HMAC(IV,key);
							byte[] bI = b_i.getBytes();
							
							cipher = xoring(mybytearray,bI);
							prev = cipher;
						}
						else
						{
							String previous = new String(prev);
							String b_i = calculateRFC2104HMAC(previous,key);
							byte [] bt = b_i.getBytes();
							cipher = xoring(mybytearray,bt);
							prev = cipher;
						}
						
						OutputStream os6 = socket.getOutputStream();
						os6.write(cipher, 0,cipher.length);
						os6.flush();

					}
					
					 Thread.sleep(4000);
					 System.out.println("File upload complete");
					 break;
				
				case 3:
					Timestamp timestamp = new Timestamp(System.currentTimeMillis());
					String time = String.valueOf(timestamp);
					
					System.out.println("Nonce send "+time);
					
					OutputStream os9= socket.getOutputStream();
					DataOutputStream dos9 = new DataOutputStream(os9);
					dos9.writeUTF(time);
					
					InputStream is9 = socket.getInputStream();
					DataInputStream in9 = new DataInputStream(is9);
					String retval = String.valueOf(in9.readUTF());
					
					Cipher cipher = Cipher.getInstance("RSA");
					PublicKey pubkey = get("public_key.der");
					
					Base64.Decoder decoder = Base64.getDecoder();
					cipher.init(Cipher.DECRYPT_MODE, pubkey);
					String decrypted = new String(cipher.doFinal(decoder.decode(retval)));
					System.out.println("Nonce received: "+decrypted);
			
					if(decrypted.equals(time))
						System.out.println("Nonce matched");
					
					System.out.println("Certificate Verification result "+verifycertificate(socket));
					break;
					
				case 4:
					generateKey(socket);
					break;		
				case 5:
					System.exit(0);
					socket.close();
					break; 

				case 6:
					File folder = new File("C:/Users/Admin/Desktop/NetworkSecurity");
         
					File[] files = folder.listFiles();
					 
					for (File file : files) 
					{
						System.out.println(file.getName());
					}
					break;
				
				case 7:
					File foldern = new File("C:/Users/Admin/Desktop/NetworkSecurity/client");
         
					File[] filesn = foldern.listFiles();
					 
					for (File file : filesn) 
					{
						System.out.println(file.getName());
					}
					break;
					
				default:
					System.out.println("Please select right option");
					break;
			}
		}
	}

		public static boolean verifycertificate(Socket socket1) throws Exception
		{
		    int filesize=1022386; 
		    int bytesRead;
			int currentTot = 0;
            byte[] bytearray = new byte [filesize]; 
            InputStream is = socket1.getInputStream(); 
            FileOutputStream fos = new FileOutputStream("copy11.crt"); 
            BufferedOutputStream bos = new BufferedOutputStream(fos); 
            bytesRead = is.read(bytearray,0,bytearray.length); 
            currentTot = bytesRead; 
            do 
            { 
                bytesRead = is.read(bytearray, currentTot, (bytearray.length-currentTot)); 
                if(bytesRead >= 0) 
                currentTot += bytesRead; 
            } while(bytesRead > -1);
            bos.write(bytearray, 0 , currentTot); 
            bos.flush();
            bos.close();
		    		
			
		try
		{
			
	        InputStream caInputStream = new FileInputStream("ashkan-certificate.crt");
	        InputStream serverCertInputStream = new FileInputStream("copy11.crt");
	        X509Certificate caCertificate = X509Certificate.getInstance(caInputStream);
	        X509Certificate serverCertificate = X509Certificate.getInstance(serverCertInputStream);
		
	        PublicKey caCertificatePublicKey = caCertificate.getPublicKey();

	        serverCertificate.checkValidity();

	        boolean result = true;
	        try {
	            serverCertificate.verify(caCertificatePublicKey);
				
				PublicKey key = serverCertificate.getPublicKey();
				byte[] pubBytes = key.getEncoded();
				KeyFactory kf = KeyFactory.getInstance("RSA");
				PublicKey pub_recovered = kf.generatePublic(new X509EncodedKeySpec(pubBytes));
			//	System.out.println("Key "+ pub_recovered.toString());
			//	System.out.println("public key algorithm = " + serverCertificate.getPublicKey().getAlgorithm());
	        } catch (Exception e) {
	            e.printStackTrace();
	            result = false;
	        }
			
			return result;
		}
		catch(Exception e1)
		{
			System.out.println(e1);
		}
        return false;
	
		}
		
		public static long  power(long  a, long  b,long  P)
		{ 
			if (b == 1)
				return a;
	 
			else
				return (((long)Math.pow(a, b)) % P);
		}
		
		public static void generateKey(Socket socket) throws Exception
		{
			Random rand = new Random();
			
			P = leftLimit + (long) (Math.random() * (rightLimit - leftLimit));
			OutputStream os11=socket.getOutputStream();
		//	System.out.println("os11 created");
			
			DataOutputStream dos11=new DataOutputStream(os11);
			dos11.writeUTF(String.valueOf(P));
		//	dos11.flush();
		//	dos11.close();
		//	System.out.println("P sent");
			
			G = leftLimit + (long) (Math.random() * (rightLimit - leftLimit));
			OutputStream os1=socket.getOutputStream();
		//	System.out.println("os1 created");
			DataOutputStream dos1=new DataOutputStream(os1);
			dos1.writeUTF(String.valueOf(G));
			dos1.flush();
		//	dos1.close();
		//	System.out.println("G sent");
			
			b = leftLimit + (long) (Math.random() * (rightLimit - leftLimit));
		//	System.out.println("The private key b for Bob : "+ b);
			
			y = power(G, b, P); // gets the generated key
			OutputStream os2=socket.getOutputStream();
			DataOutputStream dos2=new DataOutputStream(os2);
			dos2.writeUTF(String.valueOf(y));
			dos2.flush();
		//	dos2.close();
		//	System.out.println("y sent"+y);
			
			InputStream is1=socket.getInputStream();
			DataInputStream dis=new DataInputStream(is1);
			x=Long.valueOf(dis.readUTF());
			
		//	System.out.println("x received"+x);
			
			kb = power(x, b, P);
			
			System.out.println("Shared Secret key for the Client is : "+ kb);
		}

		private static byte[] xoring(byte[] data, byte[] key)
		{
			byte [] res = new byte[data.length];
			for( int i = 0; i < data.length; i++ )
			{
				res[i] = (byte)(data[i] ^ key[i % (key.length -1)]);
			//	System.out.println(res[i]);
			}
			return res;
		}
		
	
	private static String toHexString(byte[] bytes) 
	{
		Formatter formatter = new Formatter();
		
		for (byte b : bytes) {
			formatter.format("%02x", b);
		}

		return formatter.toString();
	}

	public static String calculateRFC2104HMAC(String data, String key)throws SignatureException, NoSuchAlgorithmException,InvalidKeyException
	{
		SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);
		Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
		mac.init(signingKey);
		return toHexString(mac.doFinal(data.getBytes()));
	}
		
	public static PublicKey get(String filename)throws Exception
	{

		byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
    }
}