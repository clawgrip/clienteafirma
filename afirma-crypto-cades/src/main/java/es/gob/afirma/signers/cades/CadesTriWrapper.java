package es.gob.afirma.signers.cades;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.Properties;
import java.util.logging.ErrorManager;
import java.util.logging.Logger;

import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/** Envoltura de firma trif&aacute;sica CAdES con tipos b&aacute;sicos (para ser invocada desde Swift u Objective-C).
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class CadesTriWrapper {

	private CadesTriWrapper() {
		// No instanciable
	}

	/** Obtiene la prefirma (en Base64) de una firma CAdES.
	 * @param signAlgorithm Algoritmo de firma.
	 * @param fileTbsAsBase64 Documento a firmar (como Base64).
	 * @param certChainAsPem Cadena de certificados del firmante (como PEM).
	 * @param extraParamsAsString Par&aacute;metros adicionales de la firma.
	 * @return Prefirma (como Base64 dentro de un JSON). */
	public static String getPresign(final String signAlgorithm,
                                    final String fileTbsAsBase64,
                                    final String certChainAsPem,
                                    final String extraParamsAsString) {
		// Contenido a firmar
		final byte[] fileTbs;
		try {
			fileTbs = Base64.getDecoder().decode(fileTbsAsBase64);
		}
		catch(final Exception e) {
			return getErrorResult("Error decodificando el Base64 de los datos a firmar", e); //$NON-NLS-1$
		}

		// Cadena de certificados
		final Collection<? extends Certificate> certs;
		try (InputStream is = new ByteArrayInputStream(certChainAsPem.getBytes(StandardCharsets.UTF_8))) {
			certs = generateCertificates(is);
		}
		catch (final Exception e) {
			return getErrorResult("Error conviertiendo la cadena de certificados PEM", e); //$NON-NLS-1$
		}
		final X509Certificate[] certChain = certs.toArray(new X509Certificate[0]);

		// Parametros de firma
		final Properties extraParams = new Properties();
		try {
			extraParams.load(new ByteArrayInputStream(extraParamsAsString.getBytes()));
		}
		catch (final Exception e) {
			return getErrorResult("Los parametros adicionales de firma no estan en el formato esperado", e); //$NON-NLS-1$
		}

		final CAdESParameters cadesParams;
		try {
			cadesParams = CAdESParameters.load(fileTbs, signAlgorithm, extraParams);
		}
		catch (final Exception e) {
			return getErrorResult("Error cargando la configuracion de firma CAdES", e); //$NON-NLS-1$
		}
		final byte[] preSign;
		try {
			preSign = CAdESTriPhaseSigner.preSign(certChain, cadesParams);
		}
		catch (final Exception e) {
			return getErrorResult("Error obteniendo la prefirma CAdES", e); //$NON-NLS-1$
		}
		return String.format(
			"{\n" + //$NON-NLS-1$
			"    \"result\": \"%s\"\n" + //$NON-NLS-1$
			"}", //$NON-NLS-1$
			Base64.getEncoder().encodeToString(preSign)
		);
	}

	/** Obtiene la postfirma (en Base64) de una firma CAdES.
	 * @param signAlgorithm Algoritmo de firma.
	 * @param fileTbsAsBase64 Documento a firmar (como Base64).
	 * @param certChainAsPem Cadena de certificados del firmante (como PEM).
	 * @param signatureAsBase64 Firma de los atributos firmados CAdES.
	 * @param preSignAsBase64 Prefirma (como Base64).
	 * @return Firma CAdES (como Base64 dentro de un JSON). */
	public static String getPostsign(final String signAlgorithm,
                                     final String fileTbsAsBase64,
                                     final String certChainAsPem,
                                     final String signatureAsBase64,
                                     final String preSignAsBase64) {
		// Contenido a firmado
		final byte[] fileTbs;
		try {
			fileTbs = Base64.getDecoder().decode(fileTbsAsBase64);
		}
		catch(final Exception e) {
			return getErrorResult("Error decodificando el Base64 de los datos firmados", e); //$NON-NLS-1$
		}

		// Cadena de certificados
		final Collection<? extends Certificate> certs;
		try (InputStream is = new ByteArrayInputStream(certChainAsPem.getBytes(StandardCharsets.UTF_8))) {
			certs = generateCertificates(is);
		}
		catch (final Exception e) {
			return getErrorResult("Error conviertiendo la cadena de certificados PEM", e); //$NON-NLS-1$
		}
		final X509Certificate[] certChain = certs.toArray(new X509Certificate[0]);

		// Firma
		final byte[] signature;
		try {
			signature = Base64.getDecoder().decode(signatureAsBase64);
		}
		catch(final Exception e) {
			return getErrorResult("Error decodificando el Base64 de la firma", e); //$NON-NLS-1$
		}

		// Prefirma
		final byte[] preSign;
		try {
			preSign = Base64.getDecoder().decode(preSignAsBase64);
		}
		catch(final Exception e) {
			return getErrorResult("Error decodificando el Base64 de la prefirma", e); //$NON-NLS-1$
		}

		final byte[] postSign;
		try {
			postSign = CAdESTriPhaseSigner.postSign(signAlgorithm, fileTbs, certChain, signature, preSign);
		}
		catch (final Exception e) {
			return getErrorResult("Error obteniendo la prefirma CAdES", e); //$NON-NLS-1$
		}
		return String.format(
			"{\n" + //$NON-NLS-1$
			"    \"result\": \"%s\"\n" + //$NON-NLS-1$
			"}", //$NON-NLS-1$
			Base64.getEncoder().encodeToString(postSign)
		);
	}

	private static Collection<? extends Certificate> generateCertificates(final InputStream is) throws CertificateException {
		// Necesita BouncyCastle para soportar los parametros de los tipos de curva esperados, intentamos usarlo de forma directa
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
		return new CertificateFactory().engineGenerateCertificates(is);
	}

	private static String getErrorResult(final String desc, final Throwable cause) {
		return String.format(
			"{\n" + //$NON-NLS-1$
			"    \"errorMessage: \": \"%s\",\r\n" + //$NON-NLS-1$
			"    \"errorTrace\": \"%s\"\n" + //$NON-NLS-1$
			"}", //$NON-NLS-1$
			desc,
			getStackTraceAsBase64String(cause)
		);
	}

	/** Obtiene una traza de error como texto codificado en Base64.
	 * @param e Causa del error.
	 * @return Traza de error como texto codificado en Base64. */
	public static String getStackTraceAsBase64String(final Throwable e) {
		try (
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			PrintStream pw = new PrintStream(baos)
		) {
			e.printStackTrace(pw);
			return Base64.getEncoder().encodeToString(baos.toByteArray());
		}
		catch (final IOException e1) {
			Logger.getLogger(ErrorManager.class.getName()).warning(
				"No se ha podido obtener la traza de error completa de la excepcion " + e.getClass().getName() + ": " + e1 //$NON-NLS-1$ //$NON-NLS-2$
			);
			return Base64.getEncoder().encodeToString(e.toString().getBytes());
		}
	}
}
