package es.gob.afirma.test.cades;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Properties;

import es.gob.afirma.core.signers.AOPkcs1Signer;
import es.gob.afirma.signers.cades.CadesTriWrapper;

/**
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestCadesTriWrapper {

	/** Main para pruebas.
	 * @param args No se usa.
	 * @throws Exception En cualquier error. */
	public static void main(final String[] args) throws Exception {

        final String documentTbsAsBase64 = Base64.getEncoder().encodeToString("Hola Mundo!".getBytes()); //$NON-NLS-1$
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

        final String extraParamsAsString =
    		"format=CAdES\n" + //$NON-NLS-1$
			"mode=implicit\n" + //$NON-NLS-1$
	        "policyIdentifier=urn:oid:2.16.724.1.3.1.1.2.1.8\n" + //$NON-NLS-1$
	        "policyIdentifierHash=7SxX3erFuH31TvAw9LZ70N7p1vA=\n" + //$NON-NLS-1$
	        "policyIdentifierHashAlgorithm=http://www.w3.org/2000/09/xmldsig#sha1\n"; //$NON-NLS-1$

        final String preSignAsBase64 = CadesTriWrapper.getPresign(signAlgorithm, documentTbsAsBase64, certChainAsPem, extraParamsAsString);

        // Firma PKCS#1
        final byte[] dataTbs = Base64.getDecoder().decode(preSignAsBase64);
        final AOPkcs1Signer signer = new AOPkcs1Signer();
		final Properties extraParams = new Properties();
		extraParams.load(new ByteArrayInputStream(extraParamsAsString.getBytes()));
        final byte[] signature = signer.sign(dataTbs, signAlgorithm, pke.getPrivateKey(), pke.getCertificateChain(), extraParams);
        final String signatureAsBase64 = Base64.getEncoder().encodeToString(signature);

        System.out.println(signatureAsBase64);

        final String signedDocumentAsBase64 = CadesTriWrapper.getPostsign(
    		signAlgorithm,
    		documentTbsAsBase64,
    		certChainAsPem,
    		signatureAsBase64,
    		preSignAsBase64
		);

        final byte[] signedDocument = Base64.getDecoder().decode(signedDocumentAsBase64);
        try (FileOutputStream fos = new FileOutputStream(File.createTempFile("TriPDF_", ".pdf"))) { //$NON-NLS-1$ //$NON-NLS-2$
        	fos.write(signedDocument);
        }
	}
}
