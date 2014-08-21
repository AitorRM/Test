import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.hsqldb.lib.MD5;

/**
 * Clase para pruebas con cadenas de texto.
 * 
 * @author AitorRM
 *
 */
public class StringTest {
	
	
	public static void main(String args[]){
		try {
			String text = "This is a test text.";
			System.out.println("Original: " + text);
			System.out.println();
			
			// Base 64
			String key = KeyGenerator.getInstance("DES").generateKey().toString();
			System.out.println("Base64 - random key: " + StringTest.textToBase64(text, key) + ". Reverse: " + StringTest.base64ToText(StringTest.textToBase64(text, key), key)); // OK
			key = MD5.encodeString("TEST_KEY", null);
			System.out.println("Base64 - key=MD5('TEST_KEY'): " + StringTest.textToBase64(text, key) + ". Reverse: " + StringTest.base64ToText(StringTest.textToBase64(text, key), key)); // OK
			System.out.println("Base64 - key='': " + StringTest.textToBase64(text, "") + ". Reverse: " + StringTest.base64ToText(StringTest.textToBase64(text, ""), "")); // Reverse Fail
			System.out.println("Base64 (no key): " + StringTest.textToBase64(text) + ". Reverse: " + StringTest.base64ToText(StringTest.textToBase64(text), "")); // Reverse Fail
			System.out.println();
			
			// Hex
			System.out.println("Hex: " + StringTest.toHex(text) + ". Reverse: " + StringTest.hexToString(StringTest.toHex(text))); // OK
			System.out.println("Hex (v2): " + StringTest.toHex_v2(text) + ". Reverse: " + StringTest.hexToString_v2(StringTest.toHex(text))); // OK
			System.out.println();
			
		}catch(Exception e){
			e.printStackTrace();
		}
	}
	
	
	/** 
	 * Codifica en Base64 una cadena de texto 
	 * @param text texto a codificar
	 * @return texto en base64
	 */
	public static String textToBase64(String text) {
		char base64Array[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
				'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
				'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
				'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
				't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
				'5', '6', '7', '8', '9', '+', '/' };

		String encodedString = "";
		byte bytes[] = text.getBytes();
		int i = 0;
		int pad = 0;

		while (i < bytes.length) {
			byte b1 = bytes[i++];
			byte b2;
			byte b3;

			if (i >= bytes.length) {
				b2 = 0;
				b3 = 0;
				pad = 2;
			} else {
				b2 = bytes[i++];
				if (i >= bytes.length) {
					b3 = 0;
					pad = 1;
				} else
					b3 = bytes[i++];
			}
			
			byte c1 = (byte) (b1 >> 2);
			byte c2 = (byte) (((b1 & 0x3) << 4) | (b2 >> 4));
			byte c3 = (byte) (((b2 & 0xf) << 2) | (b3 >> 6));
			byte c4 = (byte) (b3 & 0x3f);
			encodedString += base64Array[c1];
			encodedString += base64Array[c2];
			
			switch (pad) {
				case 0:
					encodedString += base64Array[c3];
					encodedString += base64Array[c4];
					break;
				case 1:
					encodedString += base64Array[c3];
					encodedString += "=";
					break;
				case 2:
					encodedString += "==";
					break;
			}
		}

		return encodedString;
	}
	
	
	/** 
	 * Codifica en Base64 una cadena de texto 
	 * @param text texto a codificar
	 * @param key clave de codificación
	 * @return texto en base64
	 */
	public static String textToBase64(String text, String keyTxt) {
		try {
			Cipher encrypt = Cipher.getInstance("DES");

			if (keyTxt == null || "".equals(keyTxt)) {
				SecretKey key = KeyGenerator.getInstance("DES").generateKey();//Genera Clave automàtica
				encrypt.init(Cipher.ENCRYPT_MODE, key);//Con clave aleatoria
			} else {
				KeySpec ks = new DESKeySpec(keyTxt.getBytes("UTF8"));
				SecretKeyFactory kf = SecretKeyFactory.getInstance("DES");
				SecretKey ky = kf.generateSecret(ks);
				encrypt.init(Cipher.ENCRYPT_MODE, ky);
			}

			// Encode the string into bytes using utf-8
			byte[] utf8 = text.getBytes("UTF8");

			// Encrypt
			byte[] enc = encrypt.doFinal(utf8);

			// Encode bytes to base64 to get a string
			return new sun.misc.BASE64Encoder().encode(enc);
			
		} catch (InvalidKeySpecException ex) {
		} catch (InvalidKeyException ex) {
		} catch (javax.crypto.BadPaddingException e) {
		} catch (IllegalBlockSizeException e) {
		} catch (UnsupportedEncodingException e) {
		} catch (NoSuchAlgorithmException ex) {
		} catch (NoSuchPaddingException ex) {
		}
		
		return null;
	}


	/** 
	 * Decodifica una cadena de texto en Base64 
	 * @param text texto en Base64
	 * @param key clave de codificación
	 * @return cadena de texto
	 */
	public static String base64ToText(String text, String keyTxt) {
		try {
			Cipher decrypt = Cipher.getInstance("DES");

			if (keyTxt.equals("")) {
				SecretKey key = KeyGenerator.getInstance("DES").generateKey();//Genera Clave automàtica
				decrypt.init(Cipher.DECRYPT_MODE, key);//Con clave aleatoria
			} else {
				KeySpec ks = new DESKeySpec(keyTxt.getBytes("UTF8"));
				SecretKeyFactory kf = SecretKeyFactory.getInstance("DES");
				SecretKey ky = kf.generateSecret(ks);
				decrypt.init(Cipher.DECRYPT_MODE, ky);
			}

			// Decode base64 to get bytes
			byte[] dec = new sun.misc.BASE64Decoder().decodeBuffer(text);

			// Decrypt
			byte[] utf8 = decrypt.doFinal(dec);

			// Decode using utf-8
			return new String(utf8, "UTF8");
		} catch (InvalidKeySpecException ex) {
		} catch (InvalidKeyException ex) {
		} catch (javax.crypto.BadPaddingException e) {
		} catch (IllegalBlockSizeException e) {
		} catch (UnsupportedEncodingException e) {
		} catch (java.io.IOException e) {
		} catch (NoSuchAlgorithmException ex) {
		} catch (NoSuchPaddingException ex) {
		}
		return null;
	}
	
	
	/**
	 * Convierte una cadena UTF-8 a formato hexadecimal.
	 * @param str
	 * @return
	 * @throws Exception
	 */
	public static String toHex(String str) throws Exception {
		if (str==null) {
			return null;
		}
		byte buf[] = str.getBytes("UTF-8");
		char[] hex_chars = "0123456789abcdef".toCharArray();
		char[] chars = new char[2 * buf.length];
        for (int i = 0; i < buf.length; ++i)
        {
            chars[2 * i] = hex_chars[(buf[i] & 0xF0) >>> 4];
            chars[2 * i + 1] = hex_chars[buf[i] & 0x0F];
        }
        return new String(chars);
	}
	
	
	/**
	 * Convierte una cadena UTF-8 a formato hexadecimal.
	 * @param cadena
	 * @return
	 * @throws Exception
	 */
	public static String toHex_v2(String str) {
		char[] chars = str.toCharArray();

		StringBuffer hex = new StringBuffer();
		for (int i = 0; i < chars.length; i++) {
			hex.append(Integer.toHexString((int) chars[i]));
		}

		return hex.toString();
	}
	
	
	/**
	 * Convierte un literal en hexadecimal a una cadena de texto en formato UTF-8
	 * @param hex Cadena en hexadecimal
	 * @return
	 * @throws Exception
	 */
	public static String hexToString(String hex) throws Exception {
		ByteBuffer buff = ByteBuffer.allocate(hex.length()/2);

		for (int i = 0; i < hex.length(); i+=2) {
		    buff.put((byte)Integer.parseInt(hex.substring(i, i+2), 16));
		}
		
		buff.rewind();
		Charset cs = Charset.forName("UTF-8");
		CharBuffer cb = cs.decode(buff);
		return cb.toString();
	}
	
	
	/**
	 * Convierte un literal en hexadecimal a una cadena de texto
	 * @param hex Cadena en hexadecimal
	 * @return
	 * @throws Exception
	 */
	public static String hexToString_v2(String hex) {
		StringBuilder sb = new StringBuilder();
		StringBuilder temp = new StringBuilder();

		for (int i = 0; i < hex.length() - 1; i += 2) {
			String output = hex.substring(i, (i + 2));
			int decimal = Integer.parseInt(output, 16);
			sb.append((char) decimal);
			temp.append(decimal);
		}

		return sb.toString();
	}
	
	
	/**
	 * Convierte un literal a un array de bytes
	 * @param hex Numero en hexadeciaml
	 * @return
	 * @throws Exception
	 */
	public static byte[] hexToBytes(String hex) throws Exception {
		byte[] bytes = new byte[hex.length() / 2];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2),
					16);
		}
		return bytes;
	}
	
	
	/**
	 * obtiene una cadena para mostrar el texto como html, 
	 * usado por ejemplo en los tooltip largos, de varias lineas, o bien en los mail
	 * @param string
	 * @return
	 */
	public static String toHtml(String string) {
		String retorno = string.replaceAll("<", "&lt;");
		retorno = retorno.replaceAll(">", "&gt;");
		retorno = retorno.replaceAll("(\r\n|\r|\n|\n\r)", "<br>");
		return retorno;
	}
	
	
	/**
	 * Convierte una cadena a un otuputstream
	 * @param cadena
	 * @return
	 * @throws Exception
	 */
	public static OutputStream toOuputStream(String cadena) throws Exception {
		OutputStream output = null;
		output = new ByteArrayOutputStream();
		output.write(cadena.getBytes("UTF-8"));
		return output;
	}
	
	
	/**
	 * Convierte una cadena a un inputStream
	 * @param cadena
	 * @return
	 * @throws Exception
	 */
	public static InputStream toInputStream(String cadena) throws Exception {
		InputStream inputStream = null;
		inputStream = new ByteArrayInputStream(cadena.getBytes("UTF-8"));
		return inputStream;
	}
}
