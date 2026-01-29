package es.gob.afirma.signers.multi.cades;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.Properties;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import es.gob.afirma.core.AOFormatFileException;
import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.signers.cades.AOCAdESSigner;

/** Prueba asociada a la incidencia #189027 de contrafirma de una firma CAdES-T. */
@SuppressWarnings("unused")
class TestINC189027 {

	private static final String FILE_CADES_T = "189027_CAdES-T.csig"; //$NON-NLS-1$
	private static final String FILE_CADES_A = "cadesA.csig"; //$NON-NLS-1$

	private static final String PKCS12_KEYSTORE = "ANCERTCCP_FIRMA.p12"; //$NON-NLS-1$
	private static final String PWD = "1111"; //$NON-NLS-1$

	private static InputStream ksIs;
	private static KeyStore ks;

	/** Carga el almac&eacute;n de certificados.
	 * @throws Exception Cuando ocurre algun problema al cargar el almac&eacute;n o los datos. */
	@BeforeAll
	void cargaAlmacen() throws Exception {
		ksIs = getClass().getClassLoader().getResourceAsStream(PKCS12_KEYSTORE);
		ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
		ks.load(ksIs, PWD.toCharArray());
	}

	/** Prueba de cofirma de una firma CAdES-T.
	 * @throws Exception Cuando ocurre un error. */
	@Test
	void testCofirmaCAdEST() throws Exception {
		final byte[] signature;
		try (InputStream is = getClass().getClassLoader().getResourceAsStream(FILE_CADES_T)) {
			signature = AOUtil.getDataFromInputStream(is);
		}

		final PrivateKeyEntry pke = (PrivateKeyEntry) ks.getEntry(ks.aliases().nextElement(), new KeyStore.PasswordProtection(PWD.toCharArray()));

		final Properties config = new Properties();
		final AOCAdESSigner signer = new AOCAdESSigner();

		final byte[] countersign;
		try (InputStream is = TestINC189027.class.getResourceAsStream("/Original.pdf")) { //$NON-NLS-1$
			countersign = signer.cosign(
				AOUtil.getDataFromInputStream(is),
				signature,
				AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA,
				pke.getPrivateKey(),
				pke.getCertificateChain(),
				config
			);
		}
		catch(final AOFormatFileException e) {
			Assertions.fail("Deberia haber cofirmado correctamente la firmas CAdES-T: " + e); //$NON-NLS-1$
			return;
		}
	}

	/** Cierra el flujo de lectura del almac&eacute;n de certificados.
	 * @throws IOException Cuando ocurre alg&uacute;n problema al cerrar el flujo de datos. */
	@SuppressWarnings("static-method")
	@AfterAll
	void cerrar() throws IOException {
		ksIs.close();
	}
}
