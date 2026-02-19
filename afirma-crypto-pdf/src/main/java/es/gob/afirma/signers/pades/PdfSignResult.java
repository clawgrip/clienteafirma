/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.signers.pades;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.GregorianCalendar;
import java.util.Properties;

import javax.xml.datatype.DatatypeFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.misc.SecureXmlBuilder;

/** Resultado de una pre-firma (como primera parte de un firma trif&aacute;sica) o una firma completa PAdES.
 * Es un <i>JavaBean</i> que encapsula los resultados de la pre-firma o firma completa PDF. */
public final class PdfSignResult {

	private final String fileID;
    private final byte[] sign;
    private final byte[] timestamp;
    private final GregorianCalendar signTime;
    private final Properties extraParams;

	/** Construye el resultado de una pre-firma (como primera parte de un firma trif&aacute;sica) o una firma completa PAdES.
	 * @param preSignAsXml Prefirma en formato XML.
	 * @throws SAXException Si hay problemas tratando los datos XML.
	 * @throws IOException Si hay problemas tratando cuanquier otro datos.
	 * @throws ParserConfigurationException Si hay problemas en la configuraci&oacute;n del analizador XML. */
	public PdfSignResult(final String preSignAsXml) throws SAXException, IOException, ParserConfigurationException {

		final ByteArrayInputStream is = new ByteArrayInputStream(preSignAsXml.getBytes(StandardCharsets.UTF_8));
    	final Document xmlSign = SecureXmlBuilder.getSecureDocumentBuilder().parse(is);
    	final NodeList nodeList = xmlSign.getChildNodes().item(0).getChildNodes();
    	int i = getNextElementNode(nodeList, 0);

    	// extraParams
    	Node node = nodeList.item(i);
    	if (!"extraParams".equalsIgnoreCase(node.getNodeName())) { //$NON-NLS-1$
    		throw new IOException("No se encontro el nodo 'extraParams' del PdfSignResultSerializado"); //$NON-NLS-1$
    	}
    	this.extraParams = AOUtil.base642Properties(node.getTextContent().trim());

    	// pdfId
    	i = getNextElementNode(nodeList, ++i);
    	node = nodeList.item(i);
    	if (!"pdfId".equalsIgnoreCase(node.getNodeName())) { //$NON-NLS-1$
    		throw new IOException("No se encontro el nodo 'pdfId' del PdfSignResultSerializado"); //$NON-NLS-1$
    	}
    	this.fileID = node.getTextContent().trim();

    	// sign
    	i = getNextElementNode(nodeList, ++i);
    	node = nodeList.item(i);
    	if (!"sign".equalsIgnoreCase(node.getNodeName())) { //$NON-NLS-1$
    		throw new IOException("No se encontro el nodo 'sign' del PdfSignResultSerializado"); //$NON-NLS-1$
    	}
    	this.sign = Base64.getDecoder().decode(node.getTextContent().trim());

    	// timestamp
    	i = getNextElementNode(nodeList, ++i);
    	node = nodeList.item(i);
    	if (!"timestamp".equalsIgnoreCase(node.getNodeName())) { //$NON-NLS-1$
    		throw new IOException(
				"No se encontro el nodo 'timestamp' del PdfSignResultSerializado, aunque no haya sello de tiempo el nodo debe existir (aunque vacio)" //$NON-NLS-1$
			);
    	}
    	this.timestamp = node.getTextContent().trim().isEmpty() ? null : Base64.getDecoder().decode(node.getTextContent().trim());

    	// signTime
    	i = getNextElementNode(nodeList, ++i);
    	node = nodeList.item(i);
    	if (!"signTime".equalsIgnoreCase(node.getNodeName())) { //$NON-NLS-1$
    		throw new IOException("No se encontro el nodo 'signTime' del PdfSignResultSerializado"); //$NON-NLS-1$
    	}

    	final DatatypeFactory dataTypeFactory;
    	try {
    		dataTypeFactory = DatatypeFactory.newInstance();
    	}
    	catch (final Exception e) {
    		throw new IOException(e);
    	}
    	this.signTime = dataTypeFactory.newXMLGregorianCalendar(node.getTextContent().trim()).toGregorianCalendar();
    }

    /** Construye el resultado de una pre-firma (como primera parte de un firma trif&aacute;sica) o una firma completa PAdES.
     * @param pdfFileId Identificador &uacute;nico del PDF
     * @param signature Firma o pre-firma
     * @param tsp Sello de tiempo
     * @param signingTime Momento de firmado
     * @param xParams Opciones adiconales de la firma */
    public PdfSignResult(final String pdfFileId,
    		             final byte[] signature,
    		             final byte[] tsp,
    		             final GregorianCalendar signingTime,
    		             final Properties xParams) {
    	if (signingTime == null) {
    		throw new IllegalArgumentException("Es obligatorio proporcionar un momento de firmado"); //$NON-NLS-1$
    	}
    	if (pdfFileId == null || pdfFileId.isEmpty()) {
    		throw new IllegalArgumentException("Es obligatorio proporcionar un MAC de PDF"); //$NON-NLS-1$
    	}
        if (signature == null || signature.length < 1) {
            throw new IllegalArgumentException("Es obligatorio una pre-firma"); //$NON-NLS-1$
        }
        this.fileID = pdfFileId;
        this.sign = signature.clone();
        this.timestamp = tsp != null ? tsp.clone() : null;
        this.signTime = signingTime;
        this.extraParams = xParams != null ? xParams : new Properties();
    }

    /** Obtiene las opciones adicionales de la firma.
     * @return Opciones adicionales de la firma. */
    Properties getExtraParams() {
    	return this.extraParams != null ? (Properties) this.extraParams.clone() : null;
    }

    /** Obtiene el FileID (<i>/ID</i>) del diccionario PDF generado.
     * @param unscaped <code>true</code> para eliminar la codificaci&oacute;n XML,
     *                 <code>false</code> para obtener el dato codificado en XML.
     * @return FileID del diccionario PDF generado */
    public String getFileID(final boolean unscaped) {
        return unscaped ? unescapeXML(this.fileID) : fileID;
    }

    /** Obtiene los atributos CAdES a firmar.
     * @return Atributos CAdES a firmar (pre-firma). */
    public byte[] getSign() {
        return this.sign.clone();
    }

    /** Obtiene el sello de tiempo.
     * @return Sello de tiempo. */
    public byte[] getTimestamp() {
    	return this.timestamp != null ? this.timestamp.clone() : null;
    }

    /** Obtiene el momento en el que se realiz&oacute; la firma.
     * @return Momento en el que se realiz&oacute; la firma. */
    GregorianCalendar getSignTime() {
    	return this.signTime;
    }

    @Override
	public String toString() {
    	final DatatypeFactory dataTypeFactory;
    	try {
    		dataTypeFactory = DatatypeFactory.newInstance();
    	}
    	catch (final Exception e) {
    		throw new IllegalStateException(e);
    	}
    	final String base64Properties;
		try {
			base64Properties = AOUtil.properties2Base64(getExtraParams());
		}
		catch (final IOException e) {
			throw new IllegalStateException(e);
		}
    	return new StringBuilder()
			.append("<signResult>\n") //$NON-NLS-1$
			.append(" <extraParams>\n") //$NON-NLS-1$
			.append(base64Properties).append('\n')
			.append(" </extraParams>\n") //$NON-NLS-1$
			.append(" <pdfId>\n") //$NON-NLS-1$
			.append(getFileID(false)).append('\n')
			.append(" </pdfId>\n") //$NON-NLS-1$
			.append(" <sign>\n") //$NON-NLS-1$
			.append(Base64.getEncoder().encodeToString(getSign())).append('\n')
			.append(" </sign>\n") //$NON-NLS-1$
			.append(" <timestamp>\n") //$NON-NLS-1$
			.append(this.timestamp != null ? Base64.getEncoder().encodeToString(getTimestamp()) : "").append('\n') //$NON-NLS-1$
			.append(" </timestamp>\n") //$NON-NLS-1$
			.append(" <signTime>\n") //$NON-NLS-1$
			.append(dataTypeFactory.newXMLGregorianCalendar(getSignTime()).toXMLFormat()).append('\n')
			.append(" </signTime>\n") //$NON-NLS-1$
			.append("</signResult>") //$NON-NLS-1$
		.toString();
    }

	/** Busca el siguiente nodo de tipo elemento del listado.
	 * @param nodeList Listado de nodos.
	 * @param initialIndex &Iacute;ndice desde el que empezar la b&uacute;squeda.
	 * @return &Iacute;ndice del nodo de tipo elemento.
	 * @throws IOException Cuando no se encuentran nodos del tipo elemento a partir del &iacute;ndice indicado. */
    private static int getNextElementNode(final NodeList nodeList, final int initialIndex) throws IOException {
    	for (int i = initialIndex; i < nodeList.getLength(); i++) {
    		final Node node = nodeList.item(i);
    		if (node.getNodeType() == Node.ELEMENT_NODE) {
    			return i;
    		}
    	}
    	throw new IOException("No se encontraron todos los campos del PdfSignResult serializado"); //$NON-NLS-1$
    }

	private static String unescapeXML(final String input) {
		if (input == null) {
			return null;
		}
		return input.replace("&amp;", "&")   //$NON-NLS-1$ //$NON-NLS-2$
				    .replace("&lt;", "<")    //$NON-NLS-1$ //$NON-NLS-2$
				    .replace("&gt;", ">")    //$NON-NLS-1$ //$NON-NLS-2$
				    .replace("&quot;", "\"") //$NON-NLS-1$ //$NON-NLS-2$
				    .replace("&apos;", "'"); //$NON-NLS-1$ //$NON-NLS-2$
	}
}