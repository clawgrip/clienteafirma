package es.gob.afirma.test.pades;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Base64;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.HashMap;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.aowagie.text.pdf.PdfReader;
import com.aowagie.text.pdf.PdfStamper;

import es.gob.afirma.core.misc.AOUtil;

/** Prueba de adici&oacute;n de XMP a un PDF.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
class TestAddingXmp {

	@SuppressWarnings("static-method")
	@Test
	void test() throws Exception {

		// PDF de ejemplo
		final PdfReader reader;
		try (InputStream is = ClassLoader.getSystemResourceAsStream("TEST_PDF.pdf")) { //$NON-NLS-1$
			reader = new PdfReader(AOUtil.getDataFromInputStream(is));
		}
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		final Calendar globalDate = new GregorianCalendar();
		final PdfStamper stamper = new PdfStamper(reader, baos, globalDate);

		final String sigDataBase64;
		try (InputStream is = ClassLoader.getSystemResourceAsStream("4df6ec6b6b5c7.jpg")) { //$NON-NLS-1$
			sigDataBase64 = Base64.getEncoder().encodeToString(AOUtil.getDataFromInputStream(is));
		}
		final HashMap<String, String> moreInfo = new HashMap<>(1);
		moreInfo.put("SignerBiometricSignatureData", sigDataBase64); //$NON-NLS-1$
		moreInfo.put("SignerBiometricSignatureFormat", "ISO 19795-7"); //$NON-NLS-1$ //$NON-NLS-2$
		moreInfo.put("SignerName", "Tom\u00E1s Garc\u00EDa-Mer\u00E1s"); //$NON-NLS-1$ //$NON-NLS-2$
		stamper.setMoreInfo(moreInfo);

		stamper.close(globalDate);
		reader.close();

        // Guardamos el resultado
        final File tmpFile = File.createTempFile("TESTXMP_", ".pdf"); //$NON-NLS-1$ //$NON-NLS-2$
        Assertions.assertNotNull(tmpFile);
        try (OutputStream fos = new FileOutputStream(tmpFile)) {
	        fos.write(baos.toByteArray());
        }
	}
}
