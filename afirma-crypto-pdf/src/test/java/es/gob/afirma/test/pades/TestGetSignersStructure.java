package es.gob.afirma.test.pades;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.core.signers.AOSigner;
import es.gob.afirma.core.util.tree.AOTreeModel;
import es.gob.afirma.core.util.tree.AOTreeNode;
import es.gob.afirma.signers.pades.AOPDFSigner;

/** Pruebas de extracci&oacute;n de firmantes de PDF firmados en los que se
 * han encontrado problemas anteriormente. */
@SuppressWarnings("static-method")
final class TestGetSignersStructure {

    private static final String CERT_PATH = "PFActivoFirSHA256.pfx"; //$NON-NLS-1$
    private static final String CERT_PASS = "12341234"; //$NON-NLS-1$
    private static final String CERT_ALIAS = "fisico activo prueba"; //$NON-NLS-1$

	private static final String[] TEST_FILES = {
//		"getSignersStructure_06-14-12020 EXP.pdf", //$NON-NLS-1$
		"getSignersStructure_INFORME ABOGACIA DEL ESTADO.pdf", //$NON-NLS-1$
		"getSignersStructure_MARZO 2015 PRIMER ENVIO.pdf", //$NON-NLS-1$
		"getSignersStructure_Sentencia 343-2012.pdf", //$NON-NLS-1$
		"pades-t.pdf" //$NON-NLS-1$
	};

	private PrivateKeyEntry pke = null;

	/** Carga la clave y certificado de firma.
	 * @throws Exception En cualquier error. */
	@BeforeEach
	void loadKeys() throws Exception {
		final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
		try (InputStream is = ClassLoader.getSystemResourceAsStream(CERT_PATH)) {
        	ks.load(is, CERT_PASS.toCharArray());
        }
        this.pke = (PrivateKeyEntry) ks.getEntry(CERT_ALIAS, new KeyStore.PasswordProtection(CERT_PASS.toCharArray()));
	}

	/** Prueba de extraccion de firmantes.
	 * @throws IOException Cuando ocurre un error al leer el fichero de pruebas.
	 * @throws Exception En cualquier error. */
	@Test
	void testGetSignersStructure() throws Exception {

		final AOSigner signer = new AOPDFSigner();

		for (final String filename : TEST_FILES) {
			final byte[] testPdf;
			try (InputStream is = ClassLoader.getSystemResourceAsStream(filename)) {
				testPdf = AOUtil.getDataFromInputStream(is);
			}

			Exception raised = null;
			AOTreeModel tree = null;
			try {
				tree = signer.getSignersStructure(testPdf, true);
			}
			catch(final Exception e) {
				raised = e;
			}

			Assertions.assertNull(raised, "Se ha lanzado una excepcion: " + raised); //$NON-NLS-1$
			Assertions.assertNotNull(tree, "No se ha devuelto el arbol de firmantes"); //$NON-NLS-1$

			final File tempFile = File.createTempFile("test", ".pdf"); //$NON-NLS-1$ //$NON-NLS-2$
			try (OutputStream fos = new FileOutputStream(tempFile)) {
				final byte[] signature = signer.sign(testPdf, AOSignConstants.SIGN_ALGORITHM_SHA1WITHRSA, this.pke.getPrivateKey(), this.pke.getCertificateChain(), null);
				fos.write(signature);
			}
			catch (final AOException e) {
				Assertions.fail("Error durante la firma con el certificado del almacen: " + filename + ":\n" + e); //$NON-NLS-1$ //$NON-NLS-2$
			}

			final AOTreeNode root = (AOTreeNode) tree.getRoot();
			if (root.getChildCount() > 0) {
				System.out.println("Fichero: " + filename + "\nFirmante: " + root.getChildAt(0) + "\nFirma guardada en: " + tempFile.getAbsolutePath() + "\n------------"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
			}
			else {
				System.out.println("Fichero: " + filename + "\nEl PDF no contiene firmas soportadas\nFirma guardada en: " + tempFile.getAbsolutePath() + "\n------------"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			}
		}
	}

	/** Prueba de extraccion de firmantes de un documento de 3 firmas, una de ellas no declaradas.
	 * La firma no declarada no debe mostrarse.
	 * @throws IOException Cuando ocurre un error al leer el fichero de pruebas.
	 * @throws Exception En cualquier error. */
	@Test
	void testGetSignersStructureFirmaNoDeclarada() throws Exception {

		final AOSigner signer = new AOPDFSigner();

		final String filename = "INC_Firma_no_declarada.pdf"; //$NON-NLS-1$
		final byte[] testPdf;
		try (InputStream is = ClassLoader.getSystemResourceAsStream(filename)) {
			testPdf = AOUtil.getDataFromInputStream(is);
		}

		AOTreeModel tree = null;
		try {
			tree = signer.getSignersStructure(testPdf, false);
		}
		catch(final Exception e) {
			Assertions.fail("Se ha lanzado una excepcion: " + e); //$NON-NLS-1$
		}

		Assertions.assertNotNull(tree, "No se ha devuelto el arbol de firmantes"); //$NON-NLS-1$

		final AOTreeNode root = (AOTreeNode) tree.getRoot();

		System.out.println("Firmas encontradas:"); //$NON-NLS-1$
		for (int i = 0; i < root.getChildCount(); i++) {
			System.out.println(" - " + root.getChildAt(i).getUserObject()); //$NON-NLS-1$
		}
		System.out.println("-------------------"); //$NON-NLS-1$

		Assertions.assertEquals(2, root.getChildCount(), "Se deben detectar las 2 firmas declaradas del documento (Carlos Gamuci y Nombre Apellido1)"); //$NON-NLS-1$
	}
}
