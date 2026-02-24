package es.gob.afirma.signers.tsp.pkcs7;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.net.URI;
import java.security.MessageDigest;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

/** Pruebas de sellos de tiempo.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
class TestTsp {

	private static final String TSP_URL = "http://tss.accv.es:8318/tsa"; //$NON-NLS-1$
	private static final boolean TSP_REQUIRECERT = true;

	public static void main(final String[] args) throws Exception {
		new TestTsp().testRfc3161TokenHttp();
	}

	/** Prueba de obtenci&oacute;n directa de <i>token</i> TSP RFC3161 por HTTP.
	 * @throws Exception En cualquier error */
	@SuppressWarnings("static-method")
	@Test
	@Disabled("Necesita TSA")
	void testRfc3161TokenHttp() throws Exception {

		final CMSTimestamper cmsTsp = new CMSTimestamper(
			TSP_REQUIRECERT,
			null,
			new URI(TSP_URL),
			null,
			null,
			null
		);
		final byte[] tspToken = cmsTsp.getTimeStampToken(
			MessageDigest.getInstance("SHA-256").digest("Hola".getBytes()), //$NON-NLS-1$ //$NON-NLS-2$
			"SHA-256", //$NON-NLS-1$
			null
		);
		try (OutputStream fos = new FileOutputStream(File.createTempFile("TSP_", ".asn1"))) { //$NON-NLS-1$ //$NON-NLS-2$
			fos.write(tspToken);
		}
		Assertions.assertNotNull(tspToken);
		System.out.println(new String(tspToken));
	}
}
