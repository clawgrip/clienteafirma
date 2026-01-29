package es.gob.afirma.test.pades;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.Properties;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.signers.pades.AOPDFSigner;

/** Pruebas espec&iacute;ficas para PDF con datos tras la marca de fin de fichero.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
final class TestTrailing {

	private static final String TEST_FILE = "TEST_PDF_Trailed.pdf"; //$NON-NLS-1$

	private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA512withRSA"; //$NON-NLS-1$

	private static final String CERT_PATH = "ANF_PF_Activo.pfx"; //$NON-NLS-1$
	private static final String CERT_PASS = "12341234"; //$NON-NLS-1$
	private static final String CERT_ALIAS = "anf usuario activo"; //$NON-NLS-1$

	/** Prueba de opciones de creaci&oacute;n de revisiones en firmas de PDF con datos tras
	 * la marca de fin de fichero.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	void testRevisionOnTrailedPdf() throws Exception {
		final byte[] testPdf;
		try (InputStream is = ClassLoader.getSystemResourceAsStream(TEST_FILE)) {
			testPdf = AOUtil.getDataFromInputStream(is);
		}
		final AOPDFSigner signer = new AOPDFSigner();

        final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
        try (InputStream is = ClassLoader.getSystemResourceAsStream(CERT_PATH)) {
        	ks.load(is, CERT_PASS.toCharArray());
        }
        final PrivateKeyEntry pke = (PrivateKeyEntry) ks.getEntry(CERT_ALIAS, new KeyStore.PasswordProtection(CERT_PASS.toCharArray()));

        final Properties extraParams = new Properties();
        extraParams.put("alwaysCreateRevision", "true"); //$NON-NLS-1$ //$NON-NLS-2$

        Exception raised = null;
        try {
	        signer.sign(
	    		testPdf,
	    		DEFAULT_SIGNATURE_ALGORITHM,
	    		pke.getPrivateKey(),
	    		pke.getCertificateChain(),
	    		extraParams
			);
        }
        catch(final Exception e) {
        	raised = e;
        }
        Assertions.assertNotNull(raised);

        extraParams.put("alwaysCreateRevision", "false"); //$NON-NLS-1$ //$NON-NLS-2$

        signer.sign(
    		testPdf,
    		DEFAULT_SIGNATURE_ALGORITHM,
    		pke.getPrivateKey(),
    		pke.getCertificateChain(),
    		extraParams
		);
	}
}
