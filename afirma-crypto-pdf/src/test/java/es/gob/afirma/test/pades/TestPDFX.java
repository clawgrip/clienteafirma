package es.gob.afirma.test.pades;

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
import es.gob.afirma.signers.pades.AOPDFSigner;

/** Pruebas espec&iacute;ficas para PDF-X.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
final class TestPDFX {

	private static final String TEST_FILE_A1A = "PDF-A.pdf"; //$NON-NLS-1$
	private static final String TEST_FILE_A1B = "PDF-A1B.pdf"; //$NON-NLS-1$
	private static final String TEST_FILE_A2B = "PDF-A2B.pdf"; //$NON-NLS-1$
	private static final String TEST_FILE_A2B_PDFTOOLS = "PDF-A2B-PdfTools.pdf"; //$NON-NLS-1$
	private static final String TEST_FILE_A3B = "PDF-A3B.pdf"; //$NON-NLS-1$

	private static final String TEST_FILE_A1B_SIGNED = "PDFA1BSIGNED.pdf"; //$NON-NLS-1$
	//private final static String TEST_FILE = "Monitorio_29-02-2016 tipoA.pdf"; //$NON-NLS-1$

	private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA512withRSA"; //$NON-NLS-1$

    private static final String CERT_PATH = "PFActivoFirSHA256.pfx"; //$NON-NLS-1$
    private static final String CERT_PASS = "12341234"; //$NON-NLS-1$
    private static final String CERT_ALIAS = "fisico activo prueba"; //$NON-NLS-1$

	/** Prueba firma de PDF con revisi&oacute;n en la primera firma.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	void testRevSignature() throws Exception {

        final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
        try (InputStream is = ClassLoader.getSystemResourceAsStream(CERT_PATH)) {
        	ks.load(is, CERT_PASS.toCharArray());
        }
        final PrivateKeyEntry pke = (PrivateKeyEntry) ks.getEntry(CERT_ALIAS, new KeyStore.PasswordProtection(CERT_PASS.toCharArray()));

		final byte[] testPdf;
		try (InputStream is = ClassLoader.getSystemResourceAsStream(TEST_FILE_A1B_SIGNED)) {
			testPdf = AOUtil.getDataFromInputStream(is);
		}
		final AOPDFSigner signer = new AOPDFSigner();

        final Properties extraParams = new Properties();
        extraParams.put("alwaysCreateRevision", "true"); //$NON-NLS-1$ //$NON-NLS-2$

        final byte[] resPdf = signer.sign(
    		testPdf,
    		DEFAULT_SIGNATURE_ALGORITHM,
    		pke.getPrivateKey(),
    		pke.getCertificateChain(),
    		extraParams
		);
        Assertions.assertNotNull(resPdf);

        try (OutputStream fos = new FileOutputStream(File.createTempFile("PDF_REV_", ".pdf"))) { //$NON-NLS-1$ //$NON-NLS-2$
        	fos.write(resPdf);
        }
	}

	/** Prueba firma de PDF-X.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	void testPdfASignature() throws Exception {

		final byte[] testPdfA2b;
		try (InputStream is = ClassLoader.getSystemResourceAsStream(TEST_FILE_A2B)) {
			testPdfA2b = AOUtil.getDataFromInputStream(is);
		}
		final AOPDFSigner signer = new AOPDFSigner();

        final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
        try (InputStream is = ClassLoader.getSystemResourceAsStream(CERT_PATH)) {
        	ks.load(is, CERT_PASS.toCharArray());
        }
        final PrivateKeyEntry pke = (PrivateKeyEntry) ks.getEntry(
    		CERT_ALIAS,
    		new KeyStore.PasswordProtection(CERT_PASS.toCharArray())
		);

        final Properties extraParams = new Properties();

        // Firma de PDF/A-2B

        byte[] resPdf = signer.sign(
    		testPdfA2b,
    		DEFAULT_SIGNATURE_ALGORITHM,
    		pke.getPrivateKey(),
    		pke.getCertificateChain(),
    		extraParams
		);
        Assertions.assertNotNull(resPdf);

        File outputFile = File.createTempFile("PDFA2BSIGNED_", ".pdf"); //$NON-NLS-1$ //$NON-NLS-2$

        try (OutputStream fos = new FileOutputStream(outputFile)) {
        	fos.write(resPdf);
        }

        System.out.println("Fichero de firma de PDF/A-2B guardado en: " + outputFile.getAbsolutePath()); //$NON-NLS-1$

        // Firma de PDF/A-1A

        final byte[] testPdfA1a;
        try (InputStream is = ClassLoader.getSystemResourceAsStream(TEST_FILE_A1A)) {
        	testPdfA1a = AOUtil.getDataFromInputStream(is);
        }

        resPdf = signer.sign(
    		testPdfA1a,
    		DEFAULT_SIGNATURE_ALGORITHM,
    		pke.getPrivateKey(),
    		pke.getCertificateChain(),
    		extraParams
		);

        outputFile = File.createTempFile("PDFA1ASIGNED_", ".pdf"); //$NON-NLS-1$ //$NON-NLS-2$

        try (OutputStream fos = new FileOutputStream(outputFile)) {
        	fos.write(resPdf);
        }

        System.out.println("Fichero de firma de PDF/A-1A guardado en: " + outputFile.getAbsolutePath()); //$NON-NLS-1$

     // Firma de PDF/A-1B

		final byte[] testPdfA1b;
		try (InputStream is = ClassLoader.getSystemResourceAsStream(TEST_FILE_A1B)) {
			testPdfA1b = AOUtil.getDataFromInputStream(is);
		}

        resPdf = signer.sign(
    		testPdfA1b,
    		DEFAULT_SIGNATURE_ALGORITHM,
    		pke.getPrivateKey(),
    		pke.getCertificateChain(),
    		extraParams
		);

        outputFile = File.createTempFile("PDFA1BSIGNED_", ".pdf"); //$NON-NLS-1$ //$NON-NLS-2$

        try (OutputStream fos = new FileOutputStream(outputFile)) {
        	fos.write(resPdf);
        }
        System.out.println("Fichero de firma de PDF/A-1B guardado en: " + outputFile.getAbsolutePath()); //$NON-NLS-1$

        // Firma de PDF/A-2B generado con PDFTools

        final byte[] testPdfAPdfTools;
        try (InputStream is = ClassLoader.getSystemResourceAsStream(TEST_FILE_A2B_PDFTOOLS)) {
        	testPdfAPdfTools = AOUtil.getDataFromInputStream(is);
        }

        resPdf = signer.sign(
    		testPdfAPdfTools,
    		DEFAULT_SIGNATURE_ALGORITHM,
    		pke.getPrivateKey(),
    		pke.getCertificateChain(),
    		extraParams
		);

        outputFile = File.createTempFile("PDFA2BPDFTOOLS_SIGNED_", ".pdf"); //$NON-NLS-1$ //$NON-NLS-2$

        try (OutputStream fos = new FileOutputStream(outputFile)) {
        	fos.write(resPdf);
        }

        System.out.println("Fichero de firma de PDF/A-2B generado con PDFtools guardado en: " + outputFile.getAbsolutePath()); //$NON-NLS-1$

        // Firma de PDF/A-3B

        final byte[] testPdfA3B;
        try (InputStream is = ClassLoader.getSystemResourceAsStream(TEST_FILE_A3B)) {
        	testPdfA3B = AOUtil.getDataFromInputStream(is);
        }

        resPdf = signer.sign(
    		testPdfA3B,
    		DEFAULT_SIGNATURE_ALGORITHM,
    		pke.getPrivateKey(),
    		pke.getCertificateChain(),
    		extraParams
		);

        outputFile = File.createTempFile("PDFA3B_SIGNED_", ".pdf"); //$NON-NLS-1$ //$NON-NLS-2$

        try (OutputStream fos = new FileOutputStream(outputFile)) {
        	fos.write(resPdf);
        }

        System.out.println("Fichero de firma de PDF/A-3B guardado en: " + outputFile.getAbsolutePath()); //$NON-NLS-1$
	}
}
