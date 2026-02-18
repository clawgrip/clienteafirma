package es.gob.afirma.test.pades;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Properties;
import java.util.logging.Logger;

import javax.xml.parsers.ParserConfigurationException;

import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.xml.sax.SAXException;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.signers.AOPkcs1Signer;
import es.gob.afirma.signers.pades.PAdESTriPhaseSigner;
import es.gob.afirma.signers.pades.PdfSignResult;

/**
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class PadesTriWrapper {

	private static final Logger LOGGER = Logger.getLogger(PadesTriWrapper.class.getName());

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

        final String preSignAsXml = getPresign(signAlgorithm, pdfTbsAsBase64, certChainAsPem, signTimeAsString, extraParamsAsString);

        final String getDataTbsAsBase64 = getDataTbsAsBase64(preSignAsXml);

        // Firma PKCS#1
        final byte[] dataTbs = Base64.getDecoder().decode(getDataTbsAsBase64);
        final AOPkcs1Signer signer = new AOPkcs1Signer();
		final Properties extraParams = new Properties();
		extraParams.load(new ByteArrayInputStream(extraParamsAsString.getBytes()));
        final byte[] signature = signer.sign(dataTbs, signAlgorithm, pke.getPrivateKey(), pke.getCertificateChain(), extraParams);
        final String signatureAsBase64 = Base64.getEncoder().encodeToString(signature);

        System.out.println(signatureAsBase64);

        final String signedPdfAsBase64 = getPostSign(signAlgorithm, pdfTbsAsBase64, certChainAsPem, signatureAsBase64, preSignAsXml);

        final byte[] signedPdf = Base64.getDecoder().decode(signedPdfAsBase64);
        try (FileOutputStream fos = new FileOutputStream(File.createTempFile("TriPDF_", ".pdf"))) { //$NON-NLS-1$ //$NON-NLS-2$
        	fos.write(signedPdf);
        }
	}

	/** Obtiene la prefirma de una firma PAdES.
	 * @param signAlgorithm Algoritmo de firma.
	 * @param pdfTbs PDF a firmar.
	 * @param certChain Cadena de certificados del firmante.
	 * @param signTime Fecha de firma.
	 * @param extraParams Par&aacute;metros adicionales de la firma.
	 * @return Prefirma.
	 * @throws IOException Si hay errores de tratamiento de datos.
	 * @throws AOException En cualquier otro error. */
	public static PdfSignResult getPresign(final String signAlgorithm,
			                               final byte[] pdfTbs,
			                               final X509Certificate[] certChain,
			                               final GregorianCalendar signTime,
			                               final Properties extraParams) throws IOException, AOException {
		return PAdESTriPhaseSigner.preSign(signAlgorithm, pdfTbs, certChain, signTime, extraParams, true);
	}

	/** Obtiene la prefirma de una firma PAdES.
	 * @param signAlgorithm Algoritmo de firma.
	 * @param pdfTbsAsBase64 PDF a firmar (como Base64).
	 * @param certChainAsPem Cadena de certificados del firmante (como PEM).
	 * @param signTimeAsString Fecha de firma (en formato 'dd/MM/yyyy HH:mm:ss').
	 * @param extraParamsAsString Par&aacute;metros adicionales de la firma.
	 * @return Prefirma (como XML). */
	public static String getPresign(final String signAlgorithm,
			                        final String pdfTbsAsBase64,
                                    final String certChainAsPem,
                                    final String signTimeAsString,
                                    final String extraParamsAsString) {
		// PDF a firmar
		final byte[] pdfTbs = Base64.getDecoder().decode(pdfTbsAsBase64);

		// Cadena de certificados
		final InputStream is = new ByteArrayInputStream(certChainAsPem.getBytes(StandardCharsets.UTF_8));
		final Collection<? extends Certificate> certs;
		try {
			certs = generateCertificates(is);
		}
		catch (final CertificateException e) {
			return getErrorResult("Error conviertiendo la cadena de certificados PEM", e); //$NON-NLS-1$
		}
		final X509Certificate[] certChain = certs.toArray(new X509Certificate[0]);

		// Fecha de firma
		final SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss"); //$NON-NLS-1$
		final Date date;
		try {
			date = sdf.parse(signTimeAsString);
		}
		catch (final ParseException e) {
			return getErrorResult("La fecha no esta en el formato esperado de 'dd/MM/yyyy HH:mm:ss' (" + signTimeAsString + ")", e); //$NON-NLS-1$ //$NON-NLS-2$
		}
		final GregorianCalendar signTime = new GregorianCalendar();
		signTime.setTime(date);

		// Parametros de firma
		final Properties extraParams = new Properties();
		try {
			extraParams.load(new ByteArrayInputStream(extraParamsAsString.getBytes()));
		}
		catch (final IOException e) {
			return getErrorResult("Los parametros adicionales de firma no estan en el formato esperado", e); //$NON-NLS-1$
		}

		try {
			return getPresign(signAlgorithm, pdfTbs, certChain, signTime, extraParams).toString();
		}
		catch (final IOException | AOException e) {
			return getErrorResult("Error obteniendo la prefirma", e); //$NON-NLS-1$
		}
	}

	/** Obtiene de una prefirma los datos a firmar.
	 * @param preSignAsXml Prefirma (como XML).
	 * @return Datos a firmar. */
	public static String getDataTbsAsBase64(final String preSignAsXml) {
		final PdfSignResult psr;
		try {
			psr = new PdfSignResult(preSignAsXml);
		}
		catch (final IOException | SAXException | ParserConfigurationException e) {
			LOGGER.severe("Error deserializando la prefirma desde el XML: " + e); //$NON-NLS-1$
			return null;
		}
		return Base64.getEncoder().encodeToString(psr.getSign());
	}

	/** Obtiene una postfirma PAdES a partir de una prefirma y la firma, generando un PDF final completo.
     * @param signAlgorithm Nombre del algoritmo de firma electr&oacute;nica (debe ser el mismo que el usado en la prefirma).
     * @param pdfTbs PDF a firmar (debe ser el mismo que el usado en la prefirma).
     * @param certChain Cadena de certificados del firmante (debe ser la misma que la usado en la prefirma).
     * @param signature Resultado de la firma de los datos de la prefirma.
     * @param preSign Resultado de la pre-firma.
     * @return PDF firmado.
     * @throws AOException En cualquier otro error.
     * @throws IOException Cuando ocurre algun error en la conversi&oacute;n o generaci&oacute;n de estructuras. */
	public static byte[] getPostSign(final String signAlgorithm,
                                     final byte[] pdfTbs,
                                     final X509Certificate[] certChain,
                                     final byte[] signature,
                                     final PdfSignResult preSign) throws AOException, IOException {
		return PAdESTriPhaseSigner.postSign(signAlgorithm, pdfTbs, certChain, signature, preSign, true);
	}

	/** Obtiene una postfirma PAdES a partir de una prefirma y la firma, generando un PDF final completo.
	 * @param signAlgorithm Nombre del algoritmo de firma electr&oacute;nica (debe ser el mismo que el usado en la prefirma).
	 * @param pdfTbsAsBase64 PDF a firmar (como Base64, debe ser el mismo que el usado en la prefirma).
	 * @param certChainAsPem Cadena de certificados del firmante (como PEM, debe ser la misma que la usado en la prefirma).
	 * @param signatureAsBase64 Resultado de la firma de los datos de la prefirma (como Base64).
	 * @param preSignAsXml Prefirma (como XML).
	 * @return Documento PDF firmado (como Base64). */
	public static String getPostSign(final String signAlgorithm,
                                     final String pdfTbsAsBase64,
                                     final String certChainAsPem,
                                     final String signatureAsBase64,
                                     final String preSignAsXml) {
		// PDF firmado
		final byte[] pdfTbs = Base64.getDecoder().decode(pdfTbsAsBase64);

		// Cadena de certificados
		final InputStream is = new ByteArrayInputStream(certChainAsPem.getBytes(StandardCharsets.UTF_8));
		final Collection<? extends Certificate> certs;
		try {
			certs = generateCertificates(is);
		}
		catch (final CertificateException e) {
			return getErrorResult("Error conviertiendo la cadena de certificados PEM", e); //$NON-NLS-1$
		}
		final X509Certificate[] certChain = certs.toArray(new X509Certificate[0]);

		// Firma
		final byte[] signature = Base64.getDecoder().decode(signatureAsBase64);

		// Prefirma
		final PdfSignResult preSign;
		try {
			preSign = new PdfSignResult(preSignAsXml);
		}
		catch (final SAXException | IOException | ParserConfigurationException e) {
			return getErrorResult("Error decodificando la prefirma", e); //$NON-NLS-1$
		}
		try {
			return Base64.getEncoder().encodeToString(getPostSign(signAlgorithm, pdfTbs, certChain, signature, preSign));
		}
		catch (final AOException | IOException e) {
			return getErrorResult("Error obteniendo la postfirma", e); //$NON-NLS-1$
		}
	}

	private static String getErrorResult(final String desc, final Throwable cause) {
		return desc + (cause != null ? ": " + cause.toString() : ""); //$NON-NLS-1$ //$NON-NLS-2$
	}

	private static Collection<? extends Certificate> generateCertificates(final InputStream is) throws CertificateException {
		// Necesita BouncyCastle para soportar los parametros de los tipos de curva esperados, intentamos usarlo de forma directa
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
		return new CertificateFactory().engineGenerateCertificates(is);
	}
}
