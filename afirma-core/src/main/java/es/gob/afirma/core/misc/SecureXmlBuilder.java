package es.gob.afirma.core.misc;

import java.util.logging.Logger;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.SAXException;

/**
 * Constructor de objetos para la carga de documentos XML.
 */
public final class SecureXmlBuilder {

	private static final Logger LOGGER = Logger.getLogger("es.gob.afirma"); //$NON-NLS-1$

	private static DocumentBuilderFactory secureBuilderFactory = null;

    private static SAXParserFactory saxFactory = null;

    private SecureXmlBuilder() {
    	// No instanciable
    }

	/**
	 * Obtiene un generador de &aacute;boles DOM con el que crear o cargar un XML.
	 * @return Generador de &aacute;rboles DOM.
	 * @throws ParserConfigurationException Cuando ocurre un error durante la creaci&oacute;n.
	 */
	public static DocumentBuilder getSecureDocumentBuilder() throws ParserConfigurationException {
		if (secureBuilderFactory == null) {
			secureBuilderFactory = DocumentBuilderFactory.newInstance();
			try {
				secureBuilderFactory.setFeature(SecureXmlConstants.FEATURE_SECURE_PROCESSING, Boolean.TRUE.booleanValue());
			}
			catch (final Exception e) {
				LOGGER.warning(()-> "No se ha podido establecer el procesado seguro en la factoria XML: " + e); //$NON-NLS-1$
			}

			// Los siguientes atributos deberia establececerlos automaticamente la implementacion de
			// la biblioteca al habilitar la caracteristica anterior. Por si acaso, los establecemos
			// expresamente
			final String[] securityProperties = {
					SecureXmlConstants.ACCESS_EXTERNAL_DTD,
					SecureXmlConstants.ACCESS_EXTERNAL_SCHEMA,
					SecureXmlConstants.ACCESS_EXTERNAL_STYLESHEET
			};
			for (final String securityProperty : securityProperties) {
				try {
					secureBuilderFactory.setAttribute(securityProperty, ""); //$NON-NLS-1$
				}
				catch (final Exception e) {
					LOGGER.warning(()-> "No se ha podido establecer una propiedad de seguridad '" + securityProperty + "' en la factoria XML: " + e); //$NON-NLS-1$ //$NON-NLS-2$
				}
			}

			secureBuilderFactory.setValidating(false);
			secureBuilderFactory.setNamespaceAware(true);
		}
		return secureBuilderFactory.newDocumentBuilder();
	}

	/**
     * Construye un parser SAX seguro que no accede a recursos externos.
     * @return Factor&iacute;a segura.
	 * @throws SAXException Cuando ocurre un error de SAX.
	 * @throws ParserConfigurationException Cuando no se puede crear el parser.
     */
	public static SAXParser getSecureSAXParser() throws ParserConfigurationException, SAXException {
		if (saxFactory == null) {
			saxFactory = SAXParserFactory.newInstance();
			try {
				saxFactory.setFeature(SecureXmlConstants.FEATURE_SECURE_PROCESSING, Boolean.TRUE.booleanValue());
			}
			catch (final Exception e) {
				LOGGER.severe(()-> "No se ha podido establecer una caracteristica de seguridad en la factoria XML: " + e); //$NON-NLS-1$
			}

			// Desactivamos las caracteristicas que permiten la carga de elementos externos
			try {
				saxFactory.setFeature("http://xml.org/sax/features/external-general-entities", false); //$NON-NLS-1$
				saxFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false); //$NON-NLS-1$
			}
			catch (final Exception e) {
				LOGGER.warning(()-> "No se ha podido establecer una caracteristica de seguridad en la factoria SAX XML: " + e); //$NON-NLS-1$
			}

			saxFactory.setValidating(false);
			saxFactory.setNamespaceAware(true);
		}
		return saxFactory.newSAXParser();
	}
}
