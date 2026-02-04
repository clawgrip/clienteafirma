/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.core.misc;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.logging.Logger;

import javax.xml.parsers.SAXParser;

import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXParseException;
import org.xml.sax.XMLReader;

/** Clase con m&eacute;todos para el trabajo con ficheros. */
public final class AOFileUtils {

	static final Logger LOGGER = Logger.getLogger(AOFileUtils.class.getName());

	private AOFileUtils() {
		// No permitimos la instanciacion
	}

	/** Guarda los datos en un temporal.
	 * @param data Datos a guardar.
	 * @return Fichero temporal.
	 * @throws IOException Cuando ocurre un error al leer los datos o crear el temporal. */
	public static File createTempFile(final byte[] data) throws IOException {

		// Creamos un fichero temporal
		final File tempFile = File.createTempFile("afirma", null); //$NON-NLS-1$
		try (OutputStream fos = new FileOutputStream(tempFile)) {
			fos.write(data);
		}
		return tempFile;
	}

	/**
	 * Comprueba si los datos proporcionados son un XML v&aacute;lido.
	 * @param data Datos a evaluar.
	 * @return {@code true} cuando los datos son un XML bien formado. {@code false}
	 * en caso contrario.
	 */
    public static boolean isXML(final byte[] data) {

    	try {
    		final SAXParser parser = SecureXmlBuilder.getSecureSAXParser();
    		final XMLReader reader = parser.getXMLReader();
    		reader.setErrorHandler(
				new ErrorHandler() {
					@Override
					public void warning(final SAXParseException e) {
						log(e);
					}
					@Override
					public void fatalError(final SAXParseException e) {
						log(e);
					}
					@Override
					public void error(final SAXParseException e) {
						log(e);
					}
					private void log(final Exception e) {
						LOGGER.fine("El documento no es un XML: " + e); //$NON-NLS-1$
					}
				}
			);
    		reader.parse(new InputSource(new ByteArrayInputStream(data)));
    	}
    	catch (final Exception e) {
    		return false;
    	}
    	return true;
    }
}
