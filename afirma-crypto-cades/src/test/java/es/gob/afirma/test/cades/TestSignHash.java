package es.gob.afirma.test.cades;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.MessageDigest;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.core.signers.AOSigner;
import es.gob.afirma.signers.cades.AOCAdESSigner;

/** Pruebas de firma de huellas. */
class TestSignHash {

	private static final String CERT_PATH = "ANF_PF_Activo.pfx"; //$NON-NLS-1$
	private static final String CERT_PASS = "12341234"; //$NON-NLS-1$
	private static final String CERT_ALIAS = "anf usuario activo"; //$NON-NLS-1$

	private static final String DATA_FILE = "txt"; //$NON-NLS-1$

	PrivateKeyEntry pke = null;

	/** Carga el almac&eacute;n de claves.
	 * @throws Exception En cualquier error. */
	@BeforeEach
	void loadResources() throws Exception {

		Logger.getLogger("es.gob.afirma").setLevel(Level.WARNING); //$NON-NLS-1$

		final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
		try (InputStream is = ClassLoader.getSystemResourceAsStream(CERT_PATH)) {
        	ks.load(is, CERT_PASS.toCharArray());
        }
		this.pke = (PrivateKeyEntry) ks.getEntry(TestSignHash.CERT_ALIAS, new KeyStore.PasswordProtection(TestSignHash.CERT_PASS.toCharArray()));
	}

	/** Prueba de firma de huella SHA-1.
	 * @throws Exception en cualquier error. */
	@Test
	void testSignHashSHA1() throws Exception {

		final String HASH_ALGORITHM = "SHA1"; //$NON-NLS-1$

		final byte[] data;
		try (InputStream is = TestCAdES.class.getResourceAsStream(TestSignHash.DATA_FILE)) {
			data = AOUtil.getDataFromInputStream(is);
		}
		final byte[] hash = MessageDigest.getInstance(HASH_ALGORITHM).digest(data);

		final Properties config = new Properties();
		config.setProperty("precalculatedHashAlgorithm", HASH_ALGORITHM); //$NON-NLS-1$

		final AOSigner signer = new AOCAdESSigner();
		final byte[] signature = signer.sign(
			hash,
			AOSignConstants.SIGN_ALGORITHM_SHA1WITHRSA,
			this.pke.getPrivateKey(),
			this.pke.getCertificateChain(),
			config
		);

		Assertions.assertNotNull(signature);

		final File outFile = File.createTempFile("signHash", ".csig"); //$NON-NLS-1$ //$NON-NLS-2$
		try (OutputStream fos = new FileOutputStream(outFile)) {
			fos.write(signature);
		}
		System.out.println("La firma de hash " + HASH_ALGORITHM + " se ha guardado en el fichero: " + outFile.getAbsolutePath()); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/** Prueba de firma de huella SHA-512.
	 * @throws Exception en cualquier error. */
	@Test
	void testSignHashSHA512() throws Exception {

		final String HASH_ALGORITHM = "SHA-512"; //$NON-NLS-1$

		final byte[] data;
		try (InputStream is = TestCAdES.class.getResourceAsStream(TestSignHash.DATA_FILE)) {
			data = AOUtil.getDataFromInputStream(is);
		}
		final byte[] hash = MessageDigest.getInstance(HASH_ALGORITHM).digest(data);

		final Properties config = new Properties();
		config.setProperty("precalculatedHashAlgorithm", HASH_ALGORITHM); //$NON-NLS-1$

		final AOSigner signer = new AOCAdESSigner();
		final byte[] signature = signer.sign(
			hash,
			AOSignConstants.SIGN_ALGORITHM_SHA1WITHRSA,
			this.pke.getPrivateKey(),
			this.pke.getCertificateChain(),
			config
		);

		Assertions.assertNotNull(signature);

		final File outFile = File.createTempFile("signHash", ".csig"); //$NON-NLS-1$ //$NON-NLS-2$
		try (OutputStream fos = new FileOutputStream(outFile)) {
			fos.write(signature);
		}

		System.out.println("La firma de hash " + HASH_ALGORITHM + " se ha guardado en el fichero: " + outFile.getAbsolutePath()); //$NON-NLS-1$ //$NON-NLS-2$
	}
}
