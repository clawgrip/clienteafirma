package es.gob.afirma.standalone.crypto;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

import org.json.JSONException;

import es.gob.afirma.core.misc.Base64;
import es.gob.afirma.standalone.SimpleErrorCode;
import es.gob.afirma.standalone.plugins.DataCipher;
import es.gob.afirma.standalone.plugins.EncryptingException;

/** Gestor para el cifrado sim&eacute;trico de datos con AES-256 (para el servidor intermedio). */
public final class AESDataCipher implements DataCipher {

	private final String jsonCipherKey;

	public AESDataCipher(final String key) {
		this.jsonCipherKey = key;
	}

	@Override
	public String cipher(final byte[] data) throws EncryptingException {
		try {
			return cipherData(data, this.jsonCipherKey);
		} catch (final Exception e) {
			throw new EncryptingException("Error durante el cifrado de los datos", e, SimpleErrorCode.Internal.ENCRYPTING_PARAMS_ERROR); //$NON-NLS-1$
		}
	}

	@Override
	public byte[] decipher(final byte[] cipheredData) throws EncryptingException {
		try {
			return decipherData(cipheredData, this.jsonCipherKey);
		} catch (final Exception e) {
			throw new EncryptingException("Error durante el descifrado de los datos", e, SimpleErrorCode.Internal.DECRYPTING_PARAMS_ERROR); //$NON-NLS-1$
		}
	}

	private static byte[] decipherData(final byte[] cypheredDataB64,
			                          final String jsonCipherKey) throws InvalidKeyException,
			                                                         GeneralSecurityException,
			                                                         IOException {
		final String recoveredData = new String(cypheredDataB64, StandardCharsets.UTF_8).replace("_", "/").replace("-", "+"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
		if (jsonCipherKey != null) {
			return decipherData(recoveredData, jsonCipherKey);
		}
		return Base64.decode(recoveredData);
	}

	/** 
	 * Descifra una cadena de datos.
	 * @param cipherKey Clave de cifrado.
	 * @return Datos descifrados.
	 * @throws InvalidKeyException Cuando la clave no es v&aacute;lida.
	 * @throws GeneralSecurityException Cuando falla el proceso de cifrado.
	 * @throws IllegalArgumentException Si los datos no se corresponden con un Base64 v&aacute;lido.
	 * @throws IOException Cuando ocurre un error en la decodificaci&oacute;n de los datos. 
	 */
	private static byte[] decipherData(final String data,
			                           final String jsonCipherKey) throws InvalidKeyException,
			                                                          GeneralSecurityException,
			                                                          IllegalArgumentException,
			                                                          IOException {

		final byte[] decipheredData = AESDesCipher.decipher(
				Base64.decode(data.replace('-', '+').replace('_', '/')),
				jsonCipherKey);

		return decipheredData;
	}

	/** 
	 * Genera una cadena con datos cifrados y codificados en base 64
	 * @param data Datos a cifrar.
	 * @param cipherKey Clave de cifrado.
	 * @return Cadena con el numero de caracteres agregados manualmente para cumplir la longitud requerida,
	 * el caracter separador y los datos cifrados y en base 64.
	 * @throws InvalidKeyException Cuando la clave no es v&aacute;lida.
	 * @throws GeneralSecurityException Cuando falla el proceso de cifrado. 
	 * @throws IOException Error en la lectura o escritura de los datos.
	 * @throws JSONException Error al tratar el JSON.
	 * */
	private static String cipherData(final byte[] data, final String cipherJSONB64) throws InvalidKeyException, 
																							GeneralSecurityException, 
																							JSONException, 
																							IOException {
		final String res = new StringBuilder()
				.append(Base64.encode(AESDesCipher.cipher(data, cipherJSONB64), true)).toString();
		
		return res;
	}
}
