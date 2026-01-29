package es.gob.afirma.signers.pades;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.Properties;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import es.gob.afirma.core.misc.AOUtil;

/** Pruebas de firma con fecha pre-establecida.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
final class TestSignTime {

	private static final String TEST_FILE = "TEST_PDF.pdf"; //$NON-NLS-1$

	private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA512withRSA"; //$NON-NLS-1$

	private static final String CERT_PATH = "PFActivoFirSHA256.pfx"; //$NON-NLS-1$
	private static final String CERT_PASS = "12341234"; //$NON-NLS-1$
	private static final String CERT_ALIAS = "fisico activo prueba"; //$NON-NLS-1$


	/** Prueba de firma con fecha pre-establecida.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	void testSignTime() throws Exception {

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
        extraParams.put("signTime", "2010:12:25:12:30:01"); //$NON-NLS-1$ //$NON-NLS-2$

        final byte[] res = signer.sign(
    		testPdf,
    		DEFAULT_SIGNATURE_ALGORITHM,
    		pke.getPrivateKey(),
    		pke.getCertificateChain(),
    		extraParams
		);

        Assertions.assertNotNull(res);

        try (OutputStream fos = new FileOutputStream(File.createTempFile("PDF_TIME_", ".pdf"))) { //$NON-NLS-1$ //$NON-NLS-2$
        	fos.write(res);
        }
	}
}
