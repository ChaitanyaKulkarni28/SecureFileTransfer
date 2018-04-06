import java.net.*; 
import java.io.*; 
import javax.crypto.*;
import java.math.*;
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

public class server extends Thread
{
  	Socket socket;
	ServerSocket serverSocket;
	Random rand = new Random();
	private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
	private static String key = "12345678910";
	private static final String IV = "ThisIsFirstPacket";
	static long leftLimit = 1000000000000000L;
	static long rightLimit = 9999999999999999L;
	static long  P, G, x, a, y, b, ka, kb, fileSize;								// P,G,y to come from client 
	static int packetsize=1024;
	static double nosofpackets;
	static byte[] cipher ;
	static byte[] prev ;
	static byte [] plaintext;
	static String integrityCheck;
	
	public server(int port) throws Exception
	{	
		serverSocket = new ServerSocket(port);
	}
	
	public void run()
	{
		int bytesRead; 
		int currentTot = 0;
		
		while(true)
		{
				
			try
			{	
			 socket = serverSocket.accept();
			key = String.valueOf(ka);	
		//	 System.out.println("Accepted connection : " + socket);
			 
			 InputStream is = socket.getInputStream();
			 DataInputStream in = new DataInputStream(is);
			 int choice = Integer.valueOf(in.readUTF());
			 
			 // 1 send 2 receive 3. certificate 4. keys 5. exit
				switch(choice)
				{
					case 1:
					
					InputStream isf = socket.getInputStream();
					DataInputStream inf = new DataInputStream(isf);
					String fname = String.valueOf(inf.readUTF());
			 
					File myFile = new File(fname);
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
							
							if(i == nosofpackets)
							{
								integrityCheck = calculateRFC2104HMAC(b_i,key);
							}
						}
						
						OutputStream os = socket.getOutputStream();
						os.write(cipher, 0,cipher.length);
						os.flush();

					}
									
					Thread.sleep(4000);
					System.out.println("File transfer complete");
					 
					OutputStream osCheck = null;
					osCheck= socket.getOutputStream();
					DataOutputStream dosCheck = new DataOutputStream(osCheck);
					dosCheck.writeUTF(integrityCheck);
					System.out.println("Integrity check value transferred");
					
					break;
				 
					case 2:
					
					InputStream isfn = socket.getInputStream();
					DataInputStream infn = new DataInputStream(isfn);
					String fnamen = String.valueOf(infn.readUTF());
					
					FileOutputStream fos = new FileOutputStream(fnamen);
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
						}
						System.out.println("Packet:"+(i+1));
						bos5.write(plaintext, 0,plaintext.length);
					}
					socket.close();
					bos5.close();
					System.out.println("File successfully uploaded");
					break;
					 
					 case 3:
					 
						Cipher cipher = Cipher.getInstance("RSA");
						PrivateKey pvtKey = getpvt("private_key.der");
						
						InputStream is9 = socket.getInputStream();
						DataInputStream in9 = new DataInputStream(is9);
						String receivedNonce = String.valueOf(in9.readUTF());
						
						cipher.init(Cipher.ENCRYPT_MODE, pvtKey);
						byte[] encrypted = cipher.doFinal(receivedNonce.getBytes());
						Base64.Encoder encoder = Base64.getEncoder();
						String encryptedString = encoder.encodeToString(encrypted);
					//	System.out.println("Encrypted: "+encryptedString);
						
						OutputStream os9= socket.getOutputStream();
						DataOutputStream dos9 = new DataOutputStream(os9);
						dos9.writeUTF(encryptedString);
						
						File transferFile1 = new File ("server-certificate.crt");
						 byte [] bytearray1 = new byte [(int)transferFile1.length()]; 
						 FileInputStream fin1 = new FileInputStream(transferFile1);
						 BufferedInputStream bin1 = new BufferedInputStream(fin1);
						 bin1.read(bytearray1,0,bytearray1.length); 
						 OutputStream os2 = socket.getOutputStream(); 
						 System.out.println("Sending Certificate...");
						 os2.write(bytearray1,0,bytearray1.length);
						 os2.flush();
						 socket.close();
						 System.out.println("Certificate transfer complete");
						 break;
						 
					case 4:
						generateKey(socket);
						break;

					case 5:
						System.exit(0);
						socket.close();
						break; 	
				}
			 
			}
			catch(Exception e1)
			{
				e1.printStackTrace();
			}
		}	
	}
    
	public static long  power(long  a, long  b,long  P)
	{ 
		if (b == 1)
			return a;
	 
		else
			return (((long)Math.pow(a, b)) % P);
	}
	
	public static void main (String [] args )
	{
		try
		{
			 Thread t = new server(6000);
			 t.start();
		}
		
		catch(Exception e)
		{
			System.out.println(e);
		}
	 	 
	}
	
	public static void generateKey(Socket socket) throws Exception
	{
		a = leftLimit + (long) (Math.random() * (rightLimit - leftLimit));		//Server private key
		
		
		
		OutputStream osX = socket.getOutputStream();			//to send x
		DataOutputStream outX = new DataOutputStream(osX);
	//	 System.out.println("outx created");
		 
		 InputStream is = socket.getInputStream();
		 DataInputStream in = new DataInputStream(is);
		 
		 InputStream isP = socket.getInputStream();
		 DataInputStream inP = new DataInputStream(isP);
		 
		 InputStream isG = socket.getInputStream();
		 DataInputStream inG = new DataInputStream(isG);
		 
		 InputStream isY = socket.getInputStream();
		 DataInputStream inY = new DataInputStream(isY);
		 
		 P = Long.valueOf(inP.readUTF());
	//	 inP.flush();
		 G = Long.valueOf(inG.readUTF());
	//	 inG.flush();
		 y = Long.valueOf(inY.readUTF());
	//	 inY.flush();
		 
	//	 System.out.println("P: "+P);
	//	 System.out.println("G: "+G);
	//	 System.out.println("Y: "+y);
	//	 System.out.println("The private key a for Server : "+ a);
		 
		 x = power(G, a, P); 													// gets the public key generated
		 
	//	 System.out.println("The public key x for Server : "+ x);
		 outX.writeUTF(String.valueOf(x));
		 outX.flush();
		 ka = power(y, a, P); 													// Shared Secret key for server
		 
		 System.out.println("Shared secret key for server: "+ka);
		 
		 socket.close();
	}
	
	//--------------------------------------------------------------------------------
	
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
	
	public static PrivateKey getpvt(String filename) throws Exception
	{

		    byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

		    PKCS8EncodedKeySpec spec =
		      new PKCS8EncodedKeySpec(keyBytes);
		    KeyFactory kf = KeyFactory.getInstance("RSA");
		    return kf.generatePrivate(spec);
	}

}