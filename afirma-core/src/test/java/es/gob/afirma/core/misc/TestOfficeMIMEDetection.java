package es.gob.afirma.core.misc;

import java.io.InputStream;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/** Pruebas de detecci&oacute;n de documentos Microsoft Office 97-2003.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
final class TestOfficeMIMEDetection {

	/** Prueba la detecci&oacute;n de documentos Excel.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	void testExcelDetection() throws Exception {
		final byte[] file;
		try (InputStream is = ClassLoader.getSystemResourceAsStream("excel.xls")) { //$NON-NLS-1$
			file = AOUtil.getDataFromInputStream(is);
		}
		final String mime = new MimeHelper(file).getMimeType();
		Assertions.assertEquals("application/vnd.ms-excel", mime, "El MIME-Type obtenido no es correcto para el fichero Excel: " + mime); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/** Prueba la detecci&oacute;n de documentos Word.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	void testWordDetection() throws Exception {
		final byte[] file;
		try (InputStream is = ClassLoader.getSystemResourceAsStream("word.doc")) { //$NON-NLS-1$
			file = AOUtil.getDataFromInputStream(is);
		}
		final String mime = new MimeHelper(file).getMimeType();
		Assertions.assertEquals("application/msword", mime, "El MIME-Type obtenido no es correcto para el fichero Word: " + mime); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/** Prueba la detecci&oacute;n de documentos Word tipo OOXML.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	void testWordOoxmlDetection() throws Exception {
		final byte[] file;
		try (InputStream is = ClassLoader.getSystemResourceAsStream("Nuevo_Documento_de_Microsoft_Word.docx")) { //$NON-NLS-1$
			file = AOUtil.getDataFromInputStream(is);
		}
		final String mime = new MimeHelper(file).getMimeType();
		Assertions.assertEquals("application/vnd.openxmlformats-officedocument.wordprocessingml.document", mime, "El MIME-Type obtenido no es correcto para el fichero Word: " + mime); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/** Prueba la detecci&oacute;n de documentos PowerPoint.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	void testPowerPointDetection() throws Exception {
		final byte[] file;
		try (InputStream is = ClassLoader.getSystemResourceAsStream("powerpoint.ppt")) { //$NON-NLS-1$
			file = AOUtil.getDataFromInputStream(is);
		}
		final String mime = new MimeHelper(file).getMimeType();
		Assertions.assertEquals("application/vnd.ms-powerpoint", mime, "El MIME-Type obtenido no es correcto para el fichero PowerPoint: " + mime); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/** Prueba la detecci&oacute;n de documentos Project.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	void testProjectDetection() throws Exception {
		final byte[] file;
		try (InputStream is = ClassLoader.getSystemResourceAsStream("project.mpp")) { //$NON-NLS-1$
			file = AOUtil.getDataFromInputStream(is);
		}
		final String mime = new MimeHelper(file).getMimeType();
		Assertions.assertEquals("application/vnd.ms-project", mime, "El MIME-Type obtenido no es correcto para el fichero Project: " + mime); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/** Prueba la detecci&oacute;n de documentos Visio.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	void testVisioDetection() throws Exception {
		final byte[] file;
		try (InputStream is = ClassLoader.getSystemResourceAsStream("visio.vsd")) { //$NON-NLS-1$
			file = AOUtil.getDataFromInputStream(is);
		}
		final String mime = new MimeHelper(file).getMimeType();
		Assertions.assertEquals("application/vnd.visio", mime, "El MIME-Type obtenido no es correcto para el fichero Visio: " + mime); //$NON-NLS-1$ //$NON-NLS-2$
	}
}
