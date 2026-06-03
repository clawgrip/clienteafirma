package es.gob.afirma.test.pades;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.signers.AOPkcs1Signer;
import es.gob.afirma.signers.pades.PadesTriWrapper;

/** Pruebas de PAdES con el recubrimiento para J2Obc.
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
        System.out.println();
        System.out.println(pdfTbsAsBase64);
        System.out.println();

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
        System.out.println();
        System.out.println(certChainAsPem);
        System.out.println();

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

        // Prefirma

        System.out.println(signAlgorithm);

        final File pdfAsTxt = File.createTempFile("pdfAsBase64_", ".txt"); //$NON-NLS-1$ //$NON-NLS-2$
        try (OutputStream fos = new FileOutputStream(pdfAsTxt)) {
        	fos.write(pdfTbsAsBase64.getBytes());
        }
        System.out.println("PDF en txt: " + pdfAsTxt.getAbsolutePath()); //$NON-NLS-1$

        System.out.println(certChainAsPem);
        System.out.println(signTimeAsString);
        System.out.println(extraParamsAsString);

        final String preSignAsXml = PadesTriWrapper.getPresign(signAlgorithm, pdfTbsAsBase64, certChainAsPem, signTimeAsString, extraParamsAsString);
        System.out.println();
        System.out.println();
        System.out.println();
        System.out.println(preSignAsXml);
        System.out.println();

        final String dataTbsAsBase64 = PadesTriWrapper.getDataTbsAsBase64(preSignAsXml);
        System.out.println();
        System.out.println();
        System.out.println();
        System.out.println(dataTbsAsBase64);
        System.out.println();

        // Firma

        final byte[] dataTbs = Base64.getDecoder().decode(dataTbsAsBase64);
        final AOPkcs1Signer signer = new AOPkcs1Signer();
        final byte[] signature = signer.sign(dataTbs, signAlgorithm, pke.getPrivateKey(), (X509Certificate[]) pke.getCertificateChain(), null);
        final String signatureAsBase64 = Base64.getEncoder().encodeToString(signature);
        System.out.println();
        System.out.println();
        System.out.println();
        System.out.println(signatureAsBase64);
        System.out.println();

        // Postfirma

        final String signedPdfAsJson = PadesTriWrapper.getPostSign(signAlgorithm, pdfTbsAsBase64, certChainAsPem, signatureAsBase64, preSignAsXml);
        final int resPos = signedPdfAsJson.indexOf("\"result\": \"") + "\"result\": \"".length(); //$NON-NLS-1$ //$NON-NLS-2$

        final byte[] signedPdf = Base64.getDecoder().decode(signedPdfAsJson.substring(resPos, signedPdfAsJson.indexOf('"',resPos)));
        final File ret = File.createTempFile("TriPDF_", ".pdf"); //$NON-NLS-1$ //$NON-NLS-2$
        try (FileOutputStream fos = new FileOutputStream(ret)) {
        	fos.write(signedPdf);
        }
        System.out.println("Temporal guardado en: " + ret.getAbsolutePath()); //$NON-NLS-1$
	}

	@SuppressWarnings("static-method")
	@Test
	void testPkcs1() throws Exception {
		for (int i=0;i<10;i++) {
	        final String signAlgorithm = "SHA256withRSA"; //$NON-NLS-1$
			final String dataTbsAsBase64 = "MYICrDAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMC8GCSqGSIb3DQEJBDEiBCA7rS3WvmPFOOdrAuQtarGiJx38Q6tifP8UBzIw5rhN8TCBrAYLKoZIhvcNAQkQAg8xgZwwgZkGCmCFVAEDAQECAQgwIDAJBgUrDgMCGgUABBPyVVU0YMI96fpUQtEPUlrwcBEWMGkwZwYLKoZIhvcNAQkQBQEWWGh0dHA6Ly9hZG1pbmlzdHJhY2lvbmVsZWN0cm9uaWNhLmdvYi5lcy9lcy9jdHQvcG9saXRpY2FmaXJtYS9wb2xpdGljYV9maXJtYV9BR0VfdjFfOC5wZGYwggGuBgsqhkiG9w0BCRACLzGCAZ0wggGZMIGKMIGHBCCp2aZ+ksZsTQ7iW8KOFwpuzeERrezjDE6eg1A1ALGCpjBjME+kTTBLMQswCQYDVQQGEwJFUzERMA8GA1UECgwIRk5NVC1SQ00xDjAMBgNVBAsMBUNlcmVzMRkwFwYDVQQDDBBBQyBGTk1UIFVzdWFyaW9zAhBI5KXKO9EVSV+j+FQU0C+oMIIBCDCB+gYKKwYBBAGsZgMKATCB6zApBggrBgEFBQcCARYdaHR0cDovL3d3dy5jZXJ0LmZubXQuZXMvZHBjcy8wgb0GCCsGAQUFBwICMIGwDIGtQ2VydGlmaWNhZG8gY3VhbGlmaWNhZG8gZGUgZmlybWEgZWxlY3Ryw7NuaWNhLiBTdWpldG8gYSBsYXMgY29uZGljaW9uZXMgZGUgdXNvIGV4cHVlc3RhcyBlbiBsYSBEUEMgZGUgbGEgRk5NVC1SQ00gY29uIE5JRjogUTI4MjYwMDQtSiAoQy9Kb3JnZSBKdWFuIDEwNi0yODAwOS1NYWRyaWQtRXNwYcOxYSkwCQYHBACL7EABAA=="; //$NON-NLS-1$
		    final String certPath = "EIDAS_CERTIFICADO_PRUEBAS___99999999R__1234.p12"; //$NON-NLS-1$
		    final String certPass = "1234"; //$NON-NLS-1$
		    final String certAlias = "eidas_certificado_pruebas___99999999r"; //$NON-NLS-1$
	        final PrivateKeyEntry pke;
	        final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
	        try (InputStream is = ClassLoader.getSystemResourceAsStream(certPath)) {
	        	ks.load(is, certPass.toCharArray());
	        }
	        pke = (PrivateKeyEntry) ks.getEntry(certAlias, new KeyStore.PasswordProtection(certPass.toCharArray()));
	        final byte[] dataTbs = Base64.getDecoder().decode(dataTbsAsBase64);
	        final AOPkcs1Signer signer = new AOPkcs1Signer();
	        final byte[] signature = signer.sign(dataTbs, signAlgorithm, pke.getPrivateKey(), (X509Certificate[]) pke.getCertificateChain(), null);
	        final String signatureAsBase64 = Base64.getEncoder().encodeToString(signature);
	        System.out.println();
	        System.out.println();
	        System.out.println();
	        System.out.println(signatureAsBase64);
	        System.out.println();
	        Assertions.assertEquals("t1zTwiMI0CwcwhuY+NzXJroMNoqk48VUALjLJgd1HN3hh77JYiIlr2n0mFVD3zDw+PEl/WkmCGoou9KkSqcK1C2Qt1T1DQKB1gAmpIM8jonjdZHXq9TAxzy5hsyLg/Z+feoUIzs3z8xwavHdfpvjr7C0i89aD/6ZU5vqVtK4Su7mSHqTOjr26EHbGOgxF0z7chum/BPGqk88ipuf3HExm4eI4QhQwLJt0JKxPx50n6KtlD6Vp/nF64nKHMjyDf19Z9zdClUFvPfwjNd5vw/O6b2t7CZGHb82go6lAmLj8EljgBedi12MLDqrI7LAgeinUsZ7EWhBz2QOmLLPD3nvgg==", signatureAsBase64); //$NON-NLS-1$
		}
	}
}
