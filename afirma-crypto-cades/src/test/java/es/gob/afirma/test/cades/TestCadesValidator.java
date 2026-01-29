package es.gob.afirma.test.cades;

import java.io.InputStream;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.signers.cades.CAdESValidator;

/** Prueba las funciones de validaci&oacute;n de firmas CAdES.
 * @author Carlos Gamuci. */
class TestCadesValidator {

	private static final String CADES_EXPLICIT_FILE = "cades_explicit.csig"; //$NON-NLS-1$
	private static final String CADES_IMPLICIT_FILE = "cades_implicit.csig"; //$NON-NLS-1$
	private static final String CADES_CLAIMED_ROLE_FILE = "cades_claimed_role.csig"; //$NON-NLS-1$

	/** Prueba la correcci&oacute;n de la identificaci&oacute;n de firmas CAdES con
	 * una firma CAdES expl&iacute;cita.
	 * @throws Exception Cuando se produce cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	void testComprobarFirmaCadesExplicit() throws Exception {
		try (InputStream is = ClassLoader.getSystemResourceAsStream(CADES_EXPLICIT_FILE)) {
			final byte[] cades = AOUtil.getDataFromInputStream(is);

			Assertions.assertTrue(
				CAdESValidator.isCAdESValid(cades, AOSignConstants.CMS_CONTENTTYPE_SIGNEDDATA, true),
				"La firma CAdES explicit no es valida" //$NON-NLS-1$
			);
		}
	}

	/** Prueba la correcci&oacute;n de la identificaci&oacute;n de firmas CAdES con
	 * una firma CAdES impl&iacute;cita.
	 * @throws Exception Cuando se produce cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	void testComprobarFirmaCadesImplicit() throws Exception {
		try (InputStream is = ClassLoader.getSystemResourceAsStream(CADES_IMPLICIT_FILE)) {
			final byte[] cades = AOUtil.getDataFromInputStream(is);
			Assertions.assertTrue(
				CAdESValidator.isCAdESValid(cades, AOSignConstants.CMS_CONTENTTYPE_SIGNEDDATA, true),
				"La firma CAdES implicit no es valida" //$NON-NLS-1$
			);
		}
	}

	/**
	 * Comprueba que una firma con ClaimedRole se considere v&aacute;lida.
	 * @throws Exception Cuando no se puede cargar la firma.
	 */
	@SuppressWarnings("static-method")
	@Test
	void testCadesSignedDataWithClaimedRole() throws Exception {
		try (InputStream is = ClassLoader.getSystemResourceAsStream(CADES_CLAIMED_ROLE_FILE)) {
			final byte[] cades = AOUtil.getDataFromInputStream(is);
			Assertions.assertTrue(
				CAdESValidator.isCAdESSignedData(cades, true),
				"No se una firma CAdES con ClaimedRole valida" //$NON-NLS-1$
			);
		}
	}
}
