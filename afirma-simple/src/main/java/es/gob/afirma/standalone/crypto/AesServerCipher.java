package es.gob.afirma.standalone.crypto;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONException;
import org.json.JSONObject;

import es.gob.afirma.core.misc.Base64;
import es.gob.afirma.standalone.plugins.ServerCipher;

/**
 * Cifra y descifra datos con el algoritmo AES.
 */
public class AesServerCipher implements ServerCipher {

	private final byte[] key;
	private final byte[] iv;

	public AesServerCipher(final String cipherConfig) throws JSONException, IOException {

		final JSONObject json = new JSONObject(cipherConfig);

		final byte[] cipherKey = Base64.decode(json.getString("key")); //$NON-NLS-1$
		final byte[] cipherIv = Base64.decode(json.getString("iv")); //$NON-NLS-1$

		this.key = cipherKey != null ? cipherKey.clone() : null;
		this.iv = cipherIv != null ? cipherIv.clone() : null;
	}

	@Override
	public byte[] decipherData(final byte[] data) throws InvalidKeyException, NoSuchAlgorithmException,
															NoSuchPaddingException, InvalidAlgorithmParameterException,
															IllegalBlockSizeException, BadPaddingException,
															GeneralSecurityException, IOException {

		final String originalB64Data = new String(data, StandardCharsets.UTF_8).replace("_", "/").replace("-", "+");   //$NON-NLS-1$//$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$

		return decipherData(originalB64Data);
	}

	@Override
	public String cipherData(final byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException,
														InvalidKeyException, InvalidAlgorithmParameterException,
														IllegalBlockSizeException, BadPaddingException {

		final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //$NON-NLS-1$
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(this.key, "AES"), new IvParameterSpec(this.iv)); //$NON-NLS-1$
		final byte[] cipheredData = cipher.doFinal(data);

		return Base64.encode(cipheredData, true);
	}

	@Override
	public byte[] decipherData(final String dataB64) throws InvalidKeyException, NoSuchAlgorithmException,
														NoSuchPaddingException, InvalidAlgorithmParameterException,
														IllegalBlockSizeException, BadPaddingException,
														GeneralSecurityException, IOException {

		final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //$NON-NLS-1$
		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(this.key, "AES"), new IvParameterSpec(this.iv)); //$NON-NLS-1$
		final byte[] decipheredData = cipher.doFinal(Base64.decode(dataB64));

		return decipheredData;
	}

}
