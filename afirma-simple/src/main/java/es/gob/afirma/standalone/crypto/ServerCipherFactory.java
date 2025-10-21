package es.gob.afirma.standalone.crypto;

import java.io.IOException;

import org.json.JSONException;
import org.json.JSONObject;

import es.gob.afirma.standalone.plugins.ServerCipher;

/**
 * Instancia clases para cifrar datos segun el algoritmo configurado por JSON.
 */
public class ServerCipherFactory {

	private static final String ALGORITHM_DES = "DES"; //$NON-NLS-1$
	private static final String ALGORITHM_AES = "AES"; //$NON-NLS-1$

	public static ServerCipher newServerCipher(final byte[] cipherConfig) throws JSONException, IOException {

		final String jsonString = new String(cipherConfig, java.nio.charset.StandardCharsets.UTF_8);

		final JSONObject json = new JSONObject(jsonString);

		final String alg = json.getString("algo"); //$NON-NLS-1$

		if (ALGORITHM_AES.equals(alg)) {
			return new AesServerCipher(jsonString);
		} else if (ALGORITHM_DES.equals(alg)) {
			return new DesServerCipher(jsonString);
		}

		return null;
	}

}
