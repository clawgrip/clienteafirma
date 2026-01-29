package es.gob.afirma.signers.pades;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class TestPdfUtils {

	/**
	 * Comprueba el funcionamiento del algoritmo de extracci&oacute;n
	 * de los rangos de p&aacute;gina.
	 */
	@SuppressWarnings("static-method")
	@Test
	void testPageRanges() {

		final int TOTAL_PAGES = 10;

		final List<Integer> pages = new ArrayList<>();
		PdfUtil.getPagesRange("7", TOTAL_PAGES, pages); //$NON-NLS-1$
		checkExpected(pages, new int[] {7});

		pages.clear();
		PdfUtil.getPagesRange(" 3 ", TOTAL_PAGES, pages); //$NON-NLS-1$
		checkExpected(pages, new int[] {3});

		pages.clear();
		PdfUtil.getPagesRange("5-8", TOTAL_PAGES, pages); //$NON-NLS-1$
		checkExpected(pages, new int[] {5, 6, 7, 8});

		pages.clear();
		PdfUtil.getPagesRange("8--1", TOTAL_PAGES, pages); //$NON-NLS-1$
		checkExpected(pages, new int[] {8, 9, 10});

		pages.clear();
		PdfUtil.getPagesRange("-3--1", TOTAL_PAGES, pages); //$NON-NLS-1$
		checkExpected(pages, new int[] {8, 9, 10});

		pages.clear();
		PdfUtil.getPagesRange(" -3 - -1 ", TOTAL_PAGES, pages); //$NON-NLS-1$
		checkExpected(pages, new int[] {8, 9, 10});

		pages.clear();
		PdfUtil.getPagesRange("0", TOTAL_PAGES, pages); //$NON-NLS-1$
		checkExpected(pages, new int[] {1});

		pages.clear();
		PdfUtil.getPagesRange("20", TOTAL_PAGES, pages); //$NON-NLS-1$
		checkExpected(pages, new int[] {TOTAL_PAGES});

		pages.clear();
		PdfUtil.getPagesRange("-20", TOTAL_PAGES, pages); //$NON-NLS-1$
		checkExpected(pages, new int[] {1});

		pages.clear();
		try {
			PdfUtil.getPagesRange("5-3", TOTAL_PAGES, pages); //$NON-NLS-1$
			Assertions.fail("Se ha aceptado un rango no valido: 5-3"); //$NON-NLS-1$
		}
		catch (final Exception e) {
			// OK
		}

		pages.clear();
		try {
			PdfUtil.getPagesRange("-1--3", TOTAL_PAGES, pages); //$NON-NLS-1$
			Assertions.fail("Se ha aceptado un rango no valido: -1--3"); //$NON-NLS-1$
		}
		catch (final Exception e) {
			// OK
		}

		pages.clear();
		try {
			PdfUtil.getPagesRange("1a-5", TOTAL_PAGES, pages); //$NON-NLS-1$
			Assertions.fail("Se ha aceptado un rango no valido: 1a-5"); //$NON-NLS-1$
		}
		catch (final Exception e) {
			// OK
		}
	}

	private static void checkExpected(final List<Integer> pagesList, final int[] expected) {

		final Integer[] pages = pagesList.toArray(new Integer[0]);

		Assertions.assertEquals(expected.length, pages.length, "No se han cargado todas las paginas del rango"); //$NON-NLS-1$

		Arrays.sort(pages);

		for (int i = 0; i < pages.length; i++) {
			Assertions.assertEquals(expected[i], pages[i].intValue(), "Encontrada pagina fuera del rango esperado"); //$NON-NLS-1$
		}
	}
}
