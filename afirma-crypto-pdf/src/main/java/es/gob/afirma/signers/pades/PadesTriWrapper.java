package es.gob.afirma.signers.pades;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
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

/** Envoltura de firma trif&aacute;sica PAdES con tipos b&aacute;sicos (para ser invocada desde Swift u Objective-C).
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class PadesTriWrapper {

	private static final Logger LOGGER = Logger.getLogger(PadesTriWrapper.class.getName());

	private PadesTriWrapper() {
		// No instanciable
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
			return PAdESTriPhaseSigner.preSign(signAlgorithm, pdfTbs, certChain, signTime, extraParams, true).toString();
		}
		catch (final IOException | AOException e) {
			return getErrorResult("Error obteniendo la prefirma", e); //$NON-NLS-1$
		}
	}

	/** Obtiene (en Base64) de una prefirma los datos a firmar.
	 * @param preSignAsXml Prefirma (como XML).
	 * @return Datos a firmar (en Base64). */
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
			return Base64.getEncoder().encodeToString(PAdESTriPhaseSigner.postSign(signAlgorithm, pdfTbs, certChain, signature, preSign, true));
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
