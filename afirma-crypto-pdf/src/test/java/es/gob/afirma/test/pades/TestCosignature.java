package es.gob.afirma.test.pades;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.Properties;
import java.util.logging.Logger;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.signers.pades.AOPDFSigner;

/** Pruebas de cofirmas. */
final class TestCosignature {

	private static final String TEST_FILE = "TEST_PDF.pdf"; //$NON-NLS-1$

	private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA512withRSA"; //$NON-NLS-1$

	private static final String CERT_PATH = "ANF_PF_Activo.pfx"; //$NON-NLS-1$
	private static final String CERT_PASS = "12341234"; //$NON-NLS-1$
	private static final String CERT_ALIAS = "anf usuario activo"; //$NON-NLS-1$

	/** Prueba de cofirma de PDF.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	void testCosignPdf() throws Exception {
		Logger.getLogger("es.gob.afirma").info( //$NON-NLS-1$
			"Prueba de cofirma PDF" //$NON-NLS-1$
		);

        final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
        try (InputStream is = ClassLoader.getSystemResourceAsStream(CERT_PATH)) {
        	ks.load(is, CERT_PASS.toCharArray());
        }
        final PrivateKeyEntry pke = (PrivateKeyEntry) ks.getEntry(CERT_ALIAS, new KeyStore.PasswordProtection(CERT_PASS.toCharArray()));

		final Properties extraParams = new Properties();

		final byte[] testPdf;
		try (InputStream is = ClassLoader.getSystemResourceAsStream(TEST_FILE)) {
			testPdf = AOUtil.getDataFromInputStream(is);
		}

		final AOPDFSigner signer = new AOPDFSigner();
		byte[] signedPdf = signer.sign(
			testPdf,
			DEFAULT_SIGNATURE_ALGORITHM,
			pke.getPrivateKey(),
			pke.getCertificateChain(),
			extraParams
		);
		Assertions.assertNotNull(signedPdf);

		File tempFile = File.createTempFile("afirmaPDF-OneSign_", ".pdf"); //$NON-NLS-1$ //$NON-NLS-2$
		try (OutputStream fos = new FileOutputStream(tempFile)) {
	        fos.write(signedPdf);
        }

		signedPdf = signer.sign(
			signedPdf,
			DEFAULT_SIGNATURE_ALGORITHM,
			pke.getPrivateKey(),
			pke.getCertificateChain(),
			extraParams
		);

		tempFile = File.createTempFile("afirmaPDF-TwoSign_", ".pdf"); //$NON-NLS-1$ //$NON-NLS-2$
		try (OutputStream fos = new FileOutputStream(tempFile)) {
	        fos.write(signedPdf);
        }
	}
}
