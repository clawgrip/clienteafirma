package es.gob.afirma.test.pades;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.Properties;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.signers.pades.AOPDFSigner;
import es.gob.afirma.signers.pades.common.PdfHasUnregisteredSignaturesException;

/** Pruebas espec&iacute;ficas para el Bug 305907.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
final class Test305907 {

	private static final String TEST_FILE = "CONVENIO.pdf"; //$NON-NLS-1$
	private static final String TEST_FILE_2 = "CONVENIO_firmado_CF.pdf"; //$NON-NLS-1$

	private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA512withRSA"; //$NON-NLS-1$

	private static final String CERT_PATH = "PFActivoFirSHA256.pfx"; //$NON-NLS-1$
	private static final String CERT_PASS = "12341234"; //$NON-NLS-1$
	private static final String CERT_ALIAS = "fisico activo prueba"; //$NON-NLS-1$

	/** Prueba de detecci&oacute;n de firmas no registradas.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Disabled
	void testReadRaw() throws Exception {

		byte[] testPdf;
		try(InputStream is = ClassLoader.getSystemResourceAsStream(TEST_FILE_2)) {
			testPdf = AOUtil.getDataFromInputStream(is);
		}

		final AOPDFSigner signer = new AOPDFSigner();
		Assertions.assertTrue(signer.isSign(testPdf));

		try (InputStream is = ClassLoader.getSystemResourceAsStream(TEST_FILE)) {
			testPdf = AOUtil.getDataFromInputStream(is);
		}
		System.setProperty("allowCosigningUnregisteredSignatures", "false"); //$NON-NLS-1$ //$NON-NLS-2$
		Assertions.assertFalse(signer.isSign(testPdf));

        final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
        try (InputStream is = ClassLoader.getSystemResourceAsStream(CERT_PATH)) {
        	ks.load(is, CERT_PASS.toCharArray());
        }
        final PrivateKeyEntry pke = (PrivateKeyEntry) ks.getEntry(CERT_ALIAS, new KeyStore.PasswordProtection(CERT_PASS.toCharArray()));

        boolean raises = false;
        try {
	        signer.sign(
	    		testPdf,
	    		DEFAULT_SIGNATURE_ALGORITHM,
	    		pke.getPrivateKey(),
	    		pke.getCertificateChain(),
	    		new Properties()
			);
        }
        catch (final PdfHasUnregisteredSignaturesException e) {
        	raises = true;
        }
        Assertions.assertTrue(raises);

        final Properties p = new Properties();
        System.setProperty("allowCosigningUnregisteredSignatures", "true"); //$NON-NLS-1$ //$NON-NLS-2$
        p.put("allowCosigningUnregisteredSignatures", "true"); //$NON-NLS-1$ //$NON-NLS-2$

        raises = false;
        try {
	        signer.sign(
	    		testPdf,
	    		DEFAULT_SIGNATURE_ALGORITHM,
	    		pke.getPrivateKey(),
	    		pke.getCertificateChain(),
	    		p
			);
        }
        catch (final PdfHasUnregisteredSignaturesException e) {
        	raises = true;
        }
        System.setProperty("allowCosigningUnregisteredSignatures", "false"); //$NON-NLS-1$ //$NON-NLS-2$
        Assertions.assertFalse(raises);
	}
}
