package es.gob.afirma.core.misc;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import es.gob.afirma.core.signers.AOSignConstants;

/** Pruebas de obtenci&oacute;n de constantes.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
final class TestConstants {

	/** Prueba de obtenci&oacute;n de nombre de algoritmo de huella <i>NONE</i>. */
	@SuppressWarnings("static-method")
	@Test
	void testDigestNone() {
		final String digestAlgo = AOSignConstants.getDigestAlgorithmName("NONEwithRSA"); //$NON-NLS-1$
		System.out.println(digestAlgo);
		Assertions.assertEquals("NONE", digestAlgo); //$NON-NLS-1$
	}
}
