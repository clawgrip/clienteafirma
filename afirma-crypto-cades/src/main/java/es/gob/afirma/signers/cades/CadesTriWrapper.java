package es.gob.afirma.signers.cades;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.Properties;

import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import es.gob.afirma.core.AOException;

/** Envoltura de firma trif&aacute;sica CAdES con tipos b&aacute;sicos (para ser invocada desde Swift u Objective-C).
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class CadesTriWrapper {

	private CadesTriWrapper() {
		// No instanciable
	}

	/** Obtiene la prefirma de una firma CAdES.
	 * @param signAlgorithm Algoritmo de firma.
	 * @param fileTbsAsBase64 Documento a firmar (como Base64).
	 * @param certChainAsPem Cadena de certificados del firmante (como PEM).
	 * @param extraParamsAsString Par&aacute;metros adicionales de la firma.
	 * @return Prefirma (como Base64). */
	public static String getPresign(final String signAlgorithm,
                                    final String fileTbsAsBase64,
                                    final String certChainAsPem,
                                    final String extraParamsAsString) {
		// Contenido a firmar
		final byte[] fileTbs = Base64.getDecoder().decode(fileTbsAsBase64);

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

		// Parametros de firma
		final Properties extraParams = new Properties();
		try {
			extraParams.load(new ByteArrayInputStream(extraParamsAsString.getBytes()));
		}
		catch (final IOException e) {
			return getErrorResult("Los parametros adicionales de firma no estan en el formato esperado", e); //$NON-NLS-1$
		}

		final CAdESParameters cadesParams;
		try {
			cadesParams = CAdESParameters.load(fileTbs, signAlgorithm, extraParams);
		}
		catch (final AOException e) {
			return getErrorResult("Error cargando la configuracion de firma CAdES", e); //$NON-NLS-1$
		}
		final byte[] preSign;
		try {
			preSign = CAdESTriPhaseSigner.preSign(certChain, cadesParams);
		}
		catch (final AOException e) {
			return getErrorResult("Error obteniendo la prefirma CAdES", e); //$NON-NLS-1$
		}
		return Base64.getEncoder().encodeToString(preSign);
	}

	public static String getPostsign(final String signAlgorithm,
                                     final String fileTbsAsBase64,
                                     final String certChainAsPem,
                                     final String signatureAsBase64,
                                     final String preSignAsBase64) {
		// Contenido a firmado
		final byte[] fileTbs = Base64.getDecoder().decode(fileTbsAsBase64);

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
		final byte[] preSign = Base64.getDecoder().decode(preSignAsBase64);

		final byte[] postSign;
		try {
			postSign = CAdESTriPhaseSigner.postSign(signAlgorithm, fileTbs, certChain, signature, preSign);
		}
		catch (final AOException e) {
			return getErrorResult("Error obteniendo la prefirma CAdES", e); //$NON-NLS-1$
		}
		return Base64.getEncoder().encodeToString(postSign);
	}

	private static Collection<? extends Certificate> generateCertificates(final InputStream is) throws CertificateException {
		// Necesita BouncyCastle para soportar los parametros de los tipos de curva esperados, intentamos usarlo de forma directa
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
		return new CertificateFactory().engineGenerateCertificates(is);
	}

	private static String getErrorResult(final String desc, final Throwable cause) {
		return desc + (cause != null ? ": " + cause.toString() : ""); //$NON-NLS-1$ //$NON-NLS-2$
	}
}
