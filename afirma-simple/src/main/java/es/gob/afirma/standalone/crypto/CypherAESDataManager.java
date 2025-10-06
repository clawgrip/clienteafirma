package es.gob.afirma.standalone.crypto;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

import org.json.JSONException;

import es.gob.afirma.core.misc.Base64;

/** Gestor para el cifrado sim&eacute;trico de datos (para el servidor intermedio). */
public final class CypherAESDataManager {

	/** 
	 * Genera una cadena con datos cifrados y codificados en base 64
	 * @param data Datos a cifrar.
	 * @param cipherKey Clave de cifrado.
	 * @return Datos cifrados en AES-256 con salto.
	 * @throws IOException Error en la lectura o escritura de los datos.
	 * @throws JSONException Error al parsear JSON.
	 * @throws GeneralSecurityException Cuando falla el proceso de cifrado 
	 */
	public static String cipherData(final byte[] data, final String cipherJSONB64) throws JSONException, 
																					IOException, 
																					GeneralSecurityException {
		
		return new StringBuilder().append(Base64.encode(AESDesCipher.cipher(data, cipherJSONB64), true)).toString();
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
				Base64.decode(data),
				jsonCipherKey);

		return decipheredData;
	}
	
	/** Descifra datos.
	 * @param cypheredDataB64 Datos cifrados (en Base64)
	 * @param cipherJSONB64 JSON con la clave de descifrado
	 * @return Datos descifrados
	 * @throws InvalidKeyException Si la clave de descifrado no es v&aacute;lida
	 * @throws GeneralSecurityException Cuando falla el proceso de cifrado
	 * @throws IOException Si hay problemas en el tratamiento de datos */
	public static byte[] decipherData(final byte[] cypheredDataB64,
			                          final String cipherJSONB64) throws InvalidKeyException,
			                                                         GeneralSecurityException,
			                                                         IOException {
		final String recoveredData = new String(cypheredDataB64, StandardCharsets.UTF_8).replace("_", "/").replace("-", "+"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
		if (cipherJSONB64 != null) {
			return decipherData(recoveredData, cipherJSONB64);
		}
		return Base64.decode(recoveredData);
	}
	
}
