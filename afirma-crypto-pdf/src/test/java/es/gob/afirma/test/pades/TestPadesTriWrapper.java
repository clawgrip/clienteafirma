package es.gob.afirma.test.pades;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Properties;

import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.signers.AOPkcs1Signer;
import es.gob.afirma.signers.pades.PadesTriWrapper;

/**
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestPadesTriWrapper {

	/** Main para pruebas.
	 * @param args No se usa.
	 * @throws Exception En cualquier error. */
	public static void main(final String[] args) throws Exception {

		final byte[] testPdf;
        try (InputStream is = ClassLoader.getSystemResourceAsStream("TEST_PDF.pdf")) { //$NON-NLS-1$
        	testPdf = AOUtil.getDataFromInputStream(is);
        }
        final String pdfTbsAsBase64 = Base64.getEncoder().encodeToString(testPdf);

        final String signAlgorithm = "SHA256withRSA"; //$NON-NLS-1$

	    final String certPath = "EIDAS_CERTIFICADO_PRUEBAS___99999999R__1234.p12"; //$NON-NLS-1$
	    final String certPass = "1234"; //$NON-NLS-1$
	    final String certAlias = "eidas_certificado_pruebas___99999999r"; //$NON-NLS-1$
        final PrivateKeyEntry pke;
        final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
        try (InputStream is = ClassLoader.getSystemResourceAsStream(certPath)) {
        	ks.load(is, certPass.toCharArray());
        }
        pke = (PrivateKeyEntry) ks.getEntry(certAlias, new KeyStore.PasswordProtection(certPass.toCharArray()));

        final StringBuilder pemChain = new StringBuilder();
        for (final Certificate cert : pke.getCertificateChain()) {
        	pemChain.append("-----BEGIN CERTIFICATE-----\n"); //$NON-NLS-1$
        	pemChain.append(Base64.getMimeEncoder().encodeToString(cert.getEncoded()));
        	pemChain.append("\n-----END CERTIFICATE-----\n"); //$NON-NLS-1$
        }
        final String certChainAsPem = pemChain.toString();

        final String signTimeAsString = "18/2/2026 16:11:00"; //$NON-NLS-1$

        final String extraParamsAsString =
    		"format=Adobe PDF\n" + //$NON-NLS-1$
			"mode=implicit\n" + //$NON-NLS-1$
			"signReason=test\n" + //$NON-NLS-1$
			"signatureProductionCity=Madrid\n" + //$NON-NLS-1$
	        "signerContact=sink@usa.net\n" + //$NON-NLS-1$
	        "policyQualifier=http://administracionelectronica.gob.es/es/ctt/politicafirma/politica_firma_AGE_v1_8.pdf\n" + //$NON-NLS-1$
	        "policyIdentifier=2.16.724.1.3.1.1.2.1.8\n" + //$NON-NLS-1$
	        "policyIdentifierHash=8lVVNGDCPen6VELRD1Ja8HARFk==\n" + //$NON-NLS-1$
	        "policyIdentifierHashAlgorithm=SHA-1\n" + //$NON-NLS-1$
	        "allowCosigningUnregisteredSignatures=true\n"; //$NON-NLS-1$

        final String preSignAsXml = PadesTriWrapper.getPresign(signAlgorithm, pdfTbsAsBase64, certChainAsPem, signTimeAsString, extraParamsAsString);

        final String getDataTbsAsBase64 = PadesTriWrapper.getDataTbsAsBase64(preSignAsXml);

        // Firma PKCS#1
        final byte[] dataTbs = Base64.getDecoder().decode(getDataTbsAsBase64);
        final AOPkcs1Signer signer = new AOPkcs1Signer();
		final Properties extraParams = new Properties();
		extraParams.load(new ByteArrayInputStream(extraParamsAsString.getBytes()));
        final byte[] signature = signer.sign(dataTbs, signAlgorithm, pke.getPrivateKey(), pke.getCertificateChain(), extraParams);
        final String signatureAsBase64 = Base64.getEncoder().encodeToString(signature);

        System.out.println(signatureAsBase64);

        final String signedPdfAsBase64 = PadesTriWrapper.getPostSign(signAlgorithm, pdfTbsAsBase64, certChainAsPem, signatureAsBase64, preSignAsXml);

        final byte[] signedPdf = Base64.getDecoder().decode(signedPdfAsBase64);
        try (FileOutputStream fos = new FileOutputStream(File.createTempFile("TriPDF_", ".pdf"))) { //$NON-NLS-1$ //$NON-NLS-2$
        	fos.write(signedPdf);
        }
	}
}
