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
import es.gob.afirma.core.misc.Base64;
import es.gob.afirma.signers.pades.AOPDFSigner;

/** Pruebas de firmas PDF visibles.
 * @author Carlos Gamuci */
public class TestSignField {

	private static final String TEST_FILE = "TEST_PDF.pdf"; //$NON-NLS-1$
	private static final String TEST_FILE_MP = "multipage.pdf"; //$NON-NLS-1$

	private static final String RUBRIC_IMAGE = "rubric.jpg"; //$NON-NLS-1$

	private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA512withRSA"; //$NON-NLS-1$

    private static final String CERT_PATH = "PFActivoFirSHA256.pfx"; //$NON-NLS-1$
    private static final String CERT_PASS = "12341234"; //$NON-NLS-1$
    private static final String CERT_ALIAS = "fisico activo prueba"; //$NON-NLS-1$

	/** Prueba de firma de PDF insertando imagen.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	void testImageOnPdf() throws Exception {
		Logger.getLogger("es.gob.afirma").info( //$NON-NLS-1$
			"Prueba de firma de PDF insertando imagen" //$NON-NLS-1$
		);

        final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
        try (InputStream is = ClassLoader.getSystemResourceAsStream(CERT_PATH)) {
        	ks.load(is, CERT_PASS.toCharArray());
        }
        final PrivateKeyEntry pke = (PrivateKeyEntry) ks.getEntry(TestSignField.CERT_ALIAS, new KeyStore.PasswordProtection(TestSignField.CERT_PASS.toCharArray()));

		final Properties extraParams = new Properties();
		extraParams.put("imagePositionOnPageLowerLeftX", "100"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("imagePositionOnPageLowerLeftY", "100"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("imagePositionOnPageUpperRightX", "200"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("imagePositionOnPageUpperRightY", "200"); //$NON-NLS-1$ //$NON-NLS-2$

		final byte[] image;
		try (InputStream is = ClassLoader.getSystemResourceAsStream("4df6ec6b6b5c7.jpg")) { //$NON-NLS-1$
			image = AOUtil.getDataFromInputStream(is);
		}
		final String imageB64 = Base64.encode(image);
		extraParams.put("image", imageB64); //$NON-NLS-1$

		extraParams.put("imagePage", "1"); //$NON-NLS-1$ //$NON-NLS-2$

		final byte[] testPdf;
		try (InputStream is = ClassLoader.getSystemResourceAsStream(TestSignField.TEST_FILE_MP)) {
			testPdf = AOUtil.getDataFromInputStream(is);
		}

		final AOPDFSigner signer = new AOPDFSigner();
		byte[] signedPdf = signer.sign(
			testPdf,
			TestSignField.DEFAULT_SIGNATURE_ALGORITHM,
			pke.getPrivateKey(),
			pke.getCertificateChain(),
			extraParams
		);
		Assertions.assertNotNull(signedPdf);

		File tempFile = File.createTempFile("afirmaPDF-IMAGEN-1_", ".pdf"); //$NON-NLS-1$ //$NON-NLS-2$

		try (OutputStream fos = new FileOutputStream(tempFile)) {
			fos.write(signedPdf);
		}

		Logger.getLogger("es.gob.afirma").info( //$NON-NLS-1$
			"Fichero temporal para la comprobacion manual del resultado: " + //$NON-NLS-1$
				tempFile.getAbsolutePath()
		);

		// Ahora con imagen en ultima pagina
		extraParams.put("imagePage", "-1"); //$NON-NLS-1$ //$NON-NLS-2$
		signedPdf = signer.sign(
			testPdf,
			TestSignField.DEFAULT_SIGNATURE_ALGORITHM,
			pke.getPrivateKey(),
			pke.getCertificateChain(),
			extraParams
		);
		tempFile = File.createTempFile("afirmaPDF-IMAGEN-LAST_", ".pdf"); //$NON-NLS-1$ //$NON-NLS-2$
		try (OutputStream fos = new FileOutputStream(tempFile)) {
			fos.write(signedPdf);
		}

		Logger.getLogger("es.gob.afirma").info( //$NON-NLS-1$
			"Fichero temporal para la comprobacion manual del resultado: " + //$NON-NLS-1$
				tempFile.getAbsolutePath()
		);

		// Y por ultimo imagen en todas las paginas
		extraParams.put("imagePage", "0"); //$NON-NLS-1$ //$NON-NLS-2$
		signedPdf = signer.sign(
			testPdf,
			TestSignField.DEFAULT_SIGNATURE_ALGORITHM,
			pke.getPrivateKey(),
			pke.getCertificateChain(),
			extraParams
		);
		tempFile = File.createTempFile("afirmaPDF-IMAGEN-TODAS_", ".pdf"); //$NON-NLS-1$ //$NON-NLS-2$
		try (OutputStream fos = new FileOutputStream(tempFile)) {
			fos.write(signedPdf);
		}

		Logger.getLogger("es.gob.afirma").info( //$NON-NLS-1$
			"Fichero temporal para la comprobacion manual del resultado: " + //$NON-NLS-1$
				tempFile.getAbsolutePath()
		);
	}

	//TODO: Averiguar porque en MAVEN no encuentra la fuente Helvetica

	/** Prueba de firma PDF visible en p&aacute;gina nueva en el PDF.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	void testNewPage() throws Exception {

		Logger.getLogger("es.gob.afirma").info( //$NON-NLS-1$
			"Prueba de firma de PDF con nueva pagina" //$NON-NLS-1$
		);

		final PrivateKeyEntry pke;

        final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
        try (InputStream is = ClassLoader.getSystemResourceAsStream(CERT_PATH)) {
        	ks.load(is, CERT_PASS.toCharArray());
        }
        pke = (PrivateKeyEntry) ks.getEntry(TestSignField.CERT_ALIAS, new KeyStore.PasswordProtection(TestSignField.CERT_PASS.toCharArray()));

		final Properties extraParams = new Properties();
		extraParams.put("signaturePage", "append"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("signaturePositionOnPageLowerLeftX", "100"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("signaturePositionOnPageLowerLeftY", "100"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("signaturePositionOnPageUpperRightX", "300"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("signaturePositionOnPageUpperRightY", "300"); //$NON-NLS-1$ //$NON-NLS-2$

		extraParams.put("layer2Text", "Firmado por $$SUBJECTCN$$ el $$SIGNDATE=dd/MM/yyyy$$."); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("layer2FontFamily", "1"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("layer2FontSize", "14"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("layer2FontStyle", "3"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("layer2FontColor", "red"); //$NON-NLS-1$ //$NON-NLS-2$

		final byte[] testPdf;
		try (InputStream is = ClassLoader.getSystemResourceAsStream(TestSignField.TEST_FILE)) {
			testPdf = AOUtil.getDataFromInputStream(is);
		}

		final AOPDFSigner signer = new AOPDFSigner();
		final byte[] signedPdf = signer.sign(
			testPdf,
			TestSignField.DEFAULT_SIGNATURE_ALGORITHM,
			pke.getPrivateKey(),
			pke.getCertificateChain(),
			extraParams
		);
		Assertions.assertNotNull(signedPdf);

		final File tempFile = File.createTempFile("afirmaPDF", ".pdf"); //$NON-NLS-1$ //$NON-NLS-2$

		try (OutputStream fos = new FileOutputStream(tempFile)) {
			fos.write(signedPdf);
		}

		Logger.getLogger("es.gob.afirma").info( //$NON-NLS-1$
			"Fichero temporal para la comprobacion manual del resultado: " + //$NON-NLS-1$
			tempFile.getAbsolutePath()
		);
	}

	/** Prueba de firma PDF visible sin r&uacute;brica.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	void testCampoDeFirmaSoloConPosiciones() throws Exception {

		Logger.getLogger("es.gob.afirma").info( //$NON-NLS-1$
			"Prueba de firma de PDF solo con posiciones de firma" //$NON-NLS-1$
		);

		final PrivateKeyEntry pke;

        final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
        try (InputStream is = ClassLoader.getSystemResourceAsStream(CERT_PATH)) {
        	ks.load(is, CERT_PASS.toCharArray());
        }
        pke = (PrivateKeyEntry) ks.getEntry(TestSignField.CERT_ALIAS, new KeyStore.PasswordProtection(TestSignField.CERT_PASS.toCharArray()));

		final Properties extraParams = new Properties();
		extraParams.put("signaturePositionOnPageLowerLeftX", "100"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("signaturePositionOnPageLowerLeftY", "100"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("signaturePositionOnPageUpperRightX", "200"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("signaturePositionOnPageUpperRightY", "200"); //$NON-NLS-1$ //$NON-NLS-2$

		final byte[] testPdf;
		try (InputStream is = ClassLoader.getSystemResourceAsStream(TestSignField.TEST_FILE)) {
			testPdf = AOUtil.getDataFromInputStream(is);
		}

		final AOPDFSigner signer = new AOPDFSigner();
		final byte[] signedPdf = signer.sign(
			testPdf,
			TestSignField.DEFAULT_SIGNATURE_ALGORITHM,
			pke.getPrivateKey(),
			pke.getCertificateChain(),
			extraParams
		);
		Assertions.assertNotNull(signedPdf);

		final File tempFile = File.createTempFile("afirmaPDF", ".pdf"); //$NON-NLS-1$ //$NON-NLS-2$

		try (OutputStream fos = new FileOutputStream(tempFile)) {
			fos.write(signedPdf);
		}

		Logger.getLogger("es.gob.afirma").info( //$NON-NLS-1$
			"Fichero temporal para la comprobacion manual del resultado: " + //$NON-NLS-1$
			tempFile.getAbsolutePath()
		);
	}

	/** Prueba de firma PDF visible con r&uacute;brica.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	void testCampoDeFirmaConPosicionesYRubrica() throws Exception {

		Logger.getLogger("es.gob.afirma").info( //$NON-NLS-1$
				"Prueba de firma de PDF con posiciones de firma y rubrica"); //$NON-NLS-1$

		final PrivateKeyEntry pke;

        final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
        try (InputStream is = ClassLoader.getSystemResourceAsStream(CERT_PATH)) {
        	ks.load(is, CERT_PASS.toCharArray());
        }
        pke = (PrivateKeyEntry) ks.getEntry(TestSignField.CERT_ALIAS, new KeyStore.PasswordProtection(TestSignField.CERT_PASS.toCharArray()));

		final Properties extraParams = new Properties();
		extraParams.put("signaturePositionOnPageLowerLeftX", "100"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("signaturePositionOnPageLowerLeftY", "100"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("signaturePositionOnPageUpperRightX", "200"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("signaturePositionOnPageUpperRightY", "200"); //$NON-NLS-1$ //$NON-NLS-2$

		final byte[] rubricImage;
		try (InputStream is = ClassLoader.getSystemResourceAsStream(TestSignField.RUBRIC_IMAGE)) {
			rubricImage = AOUtil.getDataFromInputStream(is);
		}

		final String rubricImageB64 = Base64.encode(rubricImage);

		extraParams.put("signatureRubricImage", rubricImageB64); //$NON-NLS-1$

		final byte[] testPdf;
		try (InputStream is = ClassLoader.getSystemResourceAsStream(TestSignField.TEST_FILE)) {
			testPdf = AOUtil.getDataFromInputStream(is);
		}

		final AOPDFSigner signer = new AOPDFSigner();
		final byte[] signedPdf = signer.sign(
			testPdf,
			TestSignField.DEFAULT_SIGNATURE_ALGORITHM,
			pke.getPrivateKey(),
			pke.getCertificateChain(),
			extraParams
		);
		Assertions.assertNotNull(signedPdf);

		final File tempFile = File.createTempFile("afirmaPDF", ".pdf"); //$NON-NLS-1$ //$NON-NLS-2$

		try (OutputStream fos = new FileOutputStream(tempFile)) {
			fos.write(signedPdf);
		}

		Logger.getLogger("es.gob.afirma").info( //$NON-NLS-1$
			"Fichero temporal para la comprobacion manual del resultado: " + //$NON-NLS-1$
			tempFile.getAbsolutePath()
		);
	}

	/** Prueba de firma PDF visible con un texto.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	void testCampoDeFirmaConPosicionesYTexto() throws Exception {

		Logger.getLogger("es.gob.afirma").info( //$NON-NLS-1$
				"Prueba de firma de PDF con posiciones de firma y texto"); //$NON-NLS-1$

		final PrivateKeyEntry pke;

        final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
        try (InputStream is = ClassLoader.getSystemResourceAsStream(CERT_PATH)) {
        	ks.load(is, CERT_PASS.toCharArray());
        }
        pke = (PrivateKeyEntry) ks.getEntry(TestSignField.CERT_ALIAS, new KeyStore.PasswordProtection(TestSignField.CERT_PASS.toCharArray()));

		final Properties extraParams = new Properties();
		extraParams.put("signaturePositionOnPageLowerLeftX", "100"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("signaturePositionOnPageLowerLeftY", "100"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("signaturePositionOnPageUpperRightX", "300"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("signaturePositionOnPageUpperRightY", "300"); //$NON-NLS-1$ //$NON-NLS-2$

		extraParams.put("layer2Text", "Firmado por $$SUBJECTCN$$ el $$SIGNDATE=dd/MM/yyyy$$."); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("layer2FontFamily", "1"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("layer2FontSize", "14"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("layer2FontStyle", "3"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("layer2FontColor", "red"); //$NON-NLS-1$ //$NON-NLS-2$

		final byte[] testPdf;
		try (InputStream is = ClassLoader.getSystemResourceAsStream(TestSignField.TEST_FILE)) {
			testPdf = AOUtil.getDataFromInputStream(is);
		}

		final AOPDFSigner signer = new AOPDFSigner();
		final byte[] signedPdf = signer.sign(
			testPdf,
			TestSignField.DEFAULT_SIGNATURE_ALGORITHM,
			pke.getPrivateKey(),
			pke.getCertificateChain(),
			extraParams
		);
		Assertions.assertNotNull(signedPdf);

		final File tempFile = File.createTempFile("afirmaPDF", ".pdf"); //$NON-NLS-1$ //$NON-NLS-2$

		try (OutputStream fos = new FileOutputStream(tempFile)) {
			fos.write(signedPdf);
		}

		Logger.getLogger("es.gob.afirma").info( //$NON-NLS-1$
				"Fichero temporal para la comprobacion manual del resultado: " + //$NON-NLS-1$
				tempFile.getAbsolutePath());
	}

	/** Prueba de firma PDF visible con r&uacute;brica y texto.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	void testCampoDeFirmaConPosicionesRubricaYTexto() throws Exception {

		Logger.getLogger("es.gob.afirma").info( //$NON-NLS-1$
				"Prueba de firma de PDF con posiciones de firma, rubrica y texto"); //$NON-NLS-1$

		final PrivateKeyEntry pke;

        final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
        try (InputStream is = ClassLoader.getSystemResourceAsStream(CERT_PATH)) {
        	ks.load(is, CERT_PASS.toCharArray());
        }
        pke = (PrivateKeyEntry) ks.getEntry(TestSignField.CERT_ALIAS, new KeyStore.PasswordProtection(TestSignField.CERT_PASS.toCharArray()));

		final Properties extraParams = new Properties();
		extraParams.put("signaturePositionOnPageLowerLeftX", "100"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("signaturePositionOnPageLowerLeftY", "100"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("signaturePositionOnPageUpperRightX", "200"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("signaturePositionOnPageUpperRightY", "200"); //$NON-NLS-1$ //$NON-NLS-2$

		final byte[] rubricImage;
		try (InputStream is = ClassLoader.getSystemResourceAsStream(TestSignField.RUBRIC_IMAGE)) {
			rubricImage = AOUtil.getDataFromInputStream(is);
		}

		final String rubricImageB64 = Base64.encode(rubricImage);

		extraParams.put("signatureRubricImage", rubricImageB64); //$NON-NLS-1$
		extraParams.put("layer2Text", "Este es el texto de prueba 'Hola Mundo'"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("layer2FontFamily", "1"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("layer2FontSize", "14"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("layer2FontStyle", "3"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("layer2FontColor", "red"); //$NON-NLS-1$ //$NON-NLS-2$

		final byte[] testPdf;
		try (InputStream is = ClassLoader.getSystemResourceAsStream(TestSignField.TEST_FILE)) {
			testPdf = AOUtil.getDataFromInputStream(is);
		}

		final AOPDFSigner signer = new AOPDFSigner();
		final byte[] signedPdf = signer.sign(
			testPdf,
			TestSignField.DEFAULT_SIGNATURE_ALGORITHM,
			pke.getPrivateKey(),
			pke.getCertificateChain(),
			extraParams
		);
		Assertions.assertNotNull(signedPdf);

		final File tempFile = File.createTempFile("afirmaPDF", ".pdf"); //$NON-NLS-1$ //$NON-NLS-2$

		try (OutputStream fos = new FileOutputStream(tempFile)) {
			fos.write(signedPdf);
		}

		Logger.getLogger("es.gob.afirma").info( //$NON-NLS-1$
			"Fichero temporal para la comprobacion manual del resultado: " + //$NON-NLS-1$
			tempFile.getAbsolutePath()
		);
	}

	/** Prueba de firma PDF visible con r&uacute;brica y texto con el recuadro rotado.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	void testCampoDeFirmaRotadoConPosicionesRubricaYTexto() throws Exception {

		Logger.getLogger("es.gob.afirma").info( //$NON-NLS-1$
				"Prueba de firma de PDF con posiciones de firma, rubrica y texto"); //$NON-NLS-1$

		final PrivateKeyEntry pke;

        final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
        try (InputStream is = ClassLoader.getSystemResourceAsStream(CERT_PATH)) {
        	ks.load(is, CERT_PASS.toCharArray());
        }
        pke = (PrivateKeyEntry) ks.getEntry(TestSignField.CERT_ALIAS, new KeyStore.PasswordProtection(TestSignField.CERT_PASS.toCharArray()));

		final Properties extraParams = new Properties();
		extraParams.put("signaturePositionOnPageLowerLeftX", "50"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("signaturePositionOnPageLowerLeftY", "50"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("signaturePositionOnPageUpperRightX", "300"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("signaturePositionOnPageUpperRightY", "400"); //$NON-NLS-1$ //$NON-NLS-2$

		extraParams.put("signatureRotation", "90"); //$NON-NLS-1$ //$NON-NLS-2$

		final byte[] rubricImage;
		try (InputStream is = ClassLoader.getSystemResourceAsStream(TestSignField.RUBRIC_IMAGE)) {
			rubricImage = AOUtil.getDataFromInputStream(is);
		}

		final String rubricImageB64 = Base64.encode(rubricImage);

		extraParams.put("signatureRubricImage", rubricImageB64); //$NON-NLS-1$
		extraParams.put("layer2Text", "Firmado por $$SUBJECTCN$$ el $$SIGNDATE=dd/MM/yyyy$$ con un certificado emitido por $$ISSUERCN$$"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("layer2FontFamily", "1"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("layer2FontSize", "14"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("layer2FontStyle", "3"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.put("layer2FontColor", "red"); //$NON-NLS-1$ //$NON-NLS-2$

		final byte[] testPdf;
		try (InputStream is = ClassLoader.getSystemResourceAsStream(TestSignField.TEST_FILE)) {
			testPdf = AOUtil.getDataFromInputStream(is);
		}

		final AOPDFSigner signer = new AOPDFSigner();
		final byte[] signedPdf = signer.sign(
			testPdf,
			TestSignField.DEFAULT_SIGNATURE_ALGORITHM,
			pke.getPrivateKey(),
			pke.getCertificateChain(),
			extraParams
		);
		Assertions.assertNotNull(signedPdf);

		final File tempFile = File.createTempFile("afirmaPDF", ".pdf"); //$NON-NLS-1$ //$NON-NLS-2$

		try (OutputStream fos = new FileOutputStream(tempFile)) {
			fos.write(signedPdf);
		}

		Logger.getLogger("es.gob.afirma").info( //$NON-NLS-1$
			"Fichero temporal para la comprobacion manual del resultado: " + //$NON-NLS-1$
			tempFile.getAbsolutePath()
		);
	}

	/** Entrada para pruebas manuales.
	 * @param args No se usa.
	 * @throws Exception En cualquier error. */
	public static void main(final String[] args) throws Exception {
		final TestSignField test = new TestSignField();
		test.testCampoDeFirmaConPosicionesRubricaYTexto();
	}
}
