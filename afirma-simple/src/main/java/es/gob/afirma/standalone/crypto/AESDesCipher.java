package es.gob.afirma.standalone.crypto;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONException;
import org.json.JSONObject;

import es.gob.afirma.core.misc.Base64;

/** Cifrador AES-256. */
public final class AESDesCipher {

	private AESDesCipher() {
		// No permitimos la instanciacion
	}


	public static byte[] cipher(final byte[] data, final String cipherJSONB64) throws InvalidKeyException, 
																						GeneralSecurityException, 
																						JSONException, 
																						IOException {
		
		final byte[] decodedBytesJSON = Base64.decode(cipherJSONB64);
		final String jsonString = new String(decodedBytesJSON, java.nio.charset.StandardCharsets.UTF_8);
		
		final JSONObject json = new JSONObject(jsonString);
		
		final byte[] iv = Base64.decode(json.getString("iv")); //$NON-NLS-1$
		final byte[] encodedKey = Base64.decode(json.getString("key")); //$NON-NLS-1$

		final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //$NON-NLS-1$
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encodedKey, "AES"), new IvParameterSpec(iv)); //$NON-NLS-1$
		final byte[] cipheredData = cipher.doFinal(data);

		return cipheredData;
	}

	public static byte[] decipher(final byte[] data, final String cipherJSONB64) throws InvalidKeyException, 
																						GeneralSecurityException, 
																						IOException {
		final byte[] decodedBytesJSON = Base64.decode(cipherJSONB64);
		final String jsonString = new String(decodedBytesJSON, java.nio.charset.StandardCharsets.UTF_8);
		
		final JSONObject json = new JSONObject(jsonString);
		
		final byte[] key = Base64.decode(json.getString("key")); //$NON-NLS-1$
		final byte[] iv = Base64.decode(json.getString("iv")); //$NON-NLS-1$

		final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //$NON-NLS-1$
		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv)); //$NON-NLS-1$
		final byte[] decipheredData = cipher.doFinal(data);

		return decipheredData;
	}


}
