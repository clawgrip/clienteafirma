/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.core.misc;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Locale;
import java.util.Properties;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

/** M&eacute;todos generales de utilidad para toda la aplicaci&oacute;n.
 * @version 0.3 */
public final class AOUtil {

    private AOUtil() {
        // No permitimos la instanciacion
    }

    private static final int BUFFER_SIZE = 4096;

    private static final Logger LOGGER = Logger.getLogger(AOUtil.class.getName());

    private static final String[] SUPPORTED_URI_SCHEMES = {
        "http", "https", "file", "urn" //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
    };

    private static final Charset DEFAULT_ENCODING = StandardCharsets.UTF_8;

    /** Caracteres aceptados en una codificaci&oacute;n Base64 seg&uacute;n la
     * <a href="http://www.faqs.org/rfcs/rfc3548.html">RFC 3548</a>.
     * Importante: A&ntilde;adimos el car&aacute;cter &tilde; porque en ciertas
     * codificaciones de Base64 est&aacute; aceptado, aunque no es nada recomendable */
    private static final String BASE_64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=_-\t\n+/0123456789\r~"; //$NON-NLS-1$

    /** Crea una URI a partir de un nombre de fichero local o una URL.
     * @param file Nombre del fichero local o URL
     * @return URI (<code>file://</code>) del fichero local o URL
     * @throws URISyntaxException Si no se puede crear una URI soportada a partir de la cadena de entrada */
    public static URI createURI(final String file) throws URISyntaxException {

        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("No se puede crear una URI a partir de un nulo"); //$NON-NLS-1$
        }

        String filename = file.trim();

        if (filename.isEmpty()) {
            throw new IllegalArgumentException("La URI no puede ser una cadena vacia"); //$NON-NLS-1$
        }

        // Cambiamos los caracteres Windows
        filename = filename.replace('\\', '/');

        // Realizamos los cambios necesarios para proteger los caracteres no
        // seguros
        // de la URL
        filename = filename
    		.replace(" ", "%20") //$NON-NLS-1$ //$NON-NLS-2$
            .replace("<", "%3C") //$NON-NLS-1$ //$NON-NLS-2$
            .replace(">", "%3E") //$NON-NLS-1$ //$NON-NLS-2$
            .replace("\"", "%22") //$NON-NLS-1$ //$NON-NLS-2$
            .replace("{", "%7B") //$NON-NLS-1$ //$NON-NLS-2$
            .replace("}", "%7D") //$NON-NLS-1$ //$NON-NLS-2$
            .replace("|", "%7C") //$NON-NLS-1$ //$NON-NLS-2$
            .replace("^", "%5E") //$NON-NLS-1$ //$NON-NLS-2$
            .replace("[", "%5B") //$NON-NLS-1$ //$NON-NLS-2$
            .replace("]", "%5D") //$NON-NLS-1$ //$NON-NLS-2$
            .replace("`", "%60"); //$NON-NLS-1$ //$NON-NLS-2$

        final URI uri = new URI(filename);

        // Comprobamos si es un esquema soportado
        final String scheme = uri.getScheme();
        for (final String element : SUPPORTED_URI_SCHEMES) {
            if (element.equals(scheme)) {
                return uri;
            }
        }

        // Si el esquema es nulo, aun puede ser un nombre de fichero valido
        // El caracter '#' debe protegerse en rutas locales
        // Miramos si el esquema es una letra, en cuyo caso seguro que es una
        // unidad de Windows ("C:", "D:", etc.), y le anado el file://
        // El caracter '#' debe protegerse en rutas locales
        if (scheme == null || scheme.length() == 1 && Character.isLetter((char) scheme.getBytes()[0])) {
            filename = filename.replace("#", "%23"); //$NON-NLS-1$ //$NON-NLS-2$
            return createURI("file://" + filename); //$NON-NLS-1$
        }

        throw new URISyntaxException(filename, "Tipo de URI no soportado"); //$NON-NLS-1$
    }

    /** Obtiene el flujo de entrada de un fichero (para su lectura) a partir de su URI.
     * @param uri URI del fichero a leer
     * @return Flujo de entrada hacia el contenido del fichero
     * @throws IOException Cuando no se ha podido abrir el fichero de datos. */
    public static InputStream loadFile(final URI uri) throws IOException {

        if (uri == null) {
            throw new IllegalArgumentException("Se ha pedido el contenido de una URI nula"); //$NON-NLS-1$
        }

        if (uri.getScheme().equals("file")) { //$NON-NLS-1$
            // Es un fichero en disco. Las URL de Java no soportan file://, con
            // lo que hay que diferenciarlo a mano

            // Retiramos el "file://" de la uri
            String path = uri.getSchemeSpecificPart();
            if (path.startsWith("//")) { //$NON-NLS-1$
                path = path.substring(2);
            }
            return new FileInputStream(new File(path));
        }

        // Es una URL
        final InputStream tmpStream = new BufferedInputStream(uri.toURL().openStream());

        // Las firmas via URL fallan en la descarga por temas de Sun, asi que
        // descargamos primero
        // y devolvemos un Stream contra un array de bytes
        final byte[] tmpBuffer = getDataFromInputStream(tmpStream);

        return new java.io.ByteArrayInputStream(tmpBuffer);
    }

    /** Lee un flujo de datos de entrada y los recupera en forma de array de bytes.
     * Se consume, pero no se cierra el flujo de datos de entrada.
     * @param input Flujo de donde se toman los datos.
     * @return Los datos obtenidos del flujo.
     * @throws IOException Cuando ocurre un problema durante la lectura. */
    public static byte[] getDataFromInputStream(final InputStream input) throws IOException {
        if (input == null) {
            return new byte[0];
        }
        int nBytes;
        final byte[] buffer = new byte[BUFFER_SIZE];
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        while ((nBytes = input.read(buffer)) != -1) {
            baos.write(buffer, 0, nBytes);
        }
        return baos.toByteArray();
    }

    /** Obtiene el nombre com&uacute;n (Common Name, CN) del titular de un certificado X&#46;509.
     * Si no se encuentra el CN, se devuelve la unidad organizativa (Organization Unit, OU).
     * @param c Certificado X&#46;509 del cual queremos obtener el nombre com&uacute;n.
     * @return Nombre com&uacute;n (Common Name, CN) del titular de un certificado X&#46;509. */
    public static String getCN(final X509Certificate c) {
        if (c == null) {
            return null;
        }
        return getCN(c.getSubjectX500Principal().toString());
    }

    /** Obtiene el nombre com&uacute;n (Common Name, CN) de un <i>Principal</i>
     * X&#46;400. Si no se encuentra el CN, se devuelve la unidad organizativa
     * (Organization Unit, OU).
     * @param principal <i>Principal</i> del cual queremos obtener el nombre
     *        com&uacute;n
     * @return Nombre com&uacute;n (Common Name, CN) de un <i>Principal</i>
     *         X&#46;400 */
    public static String getCN(final String principal) {
        if (principal == null) {
            return null;
        }

        String rdn = getRDNvalueFromLdapName("cn", principal); //$NON-NLS-1$
        if (rdn == null) {
            rdn = getRDNvalueFromLdapName("ou", principal); //$NON-NLS-1$
        }

        if (rdn != null) {
            return rdn;
        }

        final int i = principal.indexOf('=');
        if (i != -1) {
            LOGGER .warning("No se ha podido obtener el Common Name ni la Organizational Unit, se devolvera el fragmento mas significativo"); //$NON-NLS-1$
            return getRDNvalueFromLdapName(principal.substring(0, i), principal);
        }

        LOGGER.warning("Principal no valido, se devolvera la entrada"); //$NON-NLS-1$
        return principal;
    }

    /** Obtiene las unidades organizativas(Organizational Unit, OU) de un <i>Principal</i> X&#46;400.
     * @param principal <i>Principal</i> del cual queremos obtener el nombre com&uacute;n
     * @return Unidad organizativa (Organizational Unit, OU) de un <i>Principal</i> X&#46;400 */
    public static String[] getOUS(final String principal) {
        if (principal == null) {
            return null;
        }

        final ArrayList<String> ousList = new ArrayList<>();

        String ou = getRDNvalueFromLdapName("ou", principal); //$NON-NLS-1$
        String principalAux = principal;
        while (ou != null) {
        	ousList.add(ou);
        	principalAux = principalAux.replace("OU=" + ou, "").replace("OU=\"" + ou, "\"") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
        						.replace("ou=" + ou, "").replace("ou=\"" + ou, "\"");  //$NON-NLS-1$//$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
        	ou = getRDNvalueFromLdapName("ou", principalAux); //$NON-NLS-1$
        }

        return ousList.toArray(new String[0]);
    }

	/** Recupera el valor de un RDN (<i>Relative Distinguished Name</i>) de un principal. El valor de retorno no incluye
     * el nombre del RDN, el igual, ni las posibles comillas que envuelvan el valor.
     * La funci&oacute;n no es sensible a la capitalizaci&oacute;n del RDN. Si no se
     * encuentra, se devuelve {@code null}.
     * @param rdn RDN que deseamos encontrar.
     * @param principal Principal del que extraer el RDN (seg&uacute;n la <a href="http://www.ietf.org/rfc/rfc4514.txt">RFC 4514</a>).
     * @return Valor del RDN indicado o {@code null} si no se encuentra. */
    public static String getRDNvalueFromLdapName(final String rdn, final String principal) {

        int offset1 = 0;
        while ((offset1 = principal.toLowerCase(Locale.US).indexOf(rdn.toLowerCase(), offset1)) != -1) {

            if (offset1 > 0 && principal.charAt(offset1-1) != ',' && principal.charAt(offset1-1) != ' ') {
                offset1++;
                continue;
            }

            offset1 += rdn.length();
            while (offset1 < principal.length() && principal.charAt(offset1) == ' ') {
                offset1++;
            }

            if (offset1 >= principal.length()) {
                return null;
            }

            if (principal.charAt(offset1) != '=') {
                continue;
            }

            offset1++;
            while (offset1 < principal.length() && principal.charAt(offset1) == ' ') {
                offset1++;
            }

            if (offset1 >= principal.length()) {
                return ""; //$NON-NLS-1$
            }

            int offset2;
            if (principal.charAt(offset1) == ',') {
                return ""; //$NON-NLS-1$
            }
			if (principal.charAt(offset1) != '"') {
			    offset2 = principal.indexOf(',', offset1);
			    if (offset2 != -1) {
			        return principal.substring(offset1, offset2).trim();
			    }
			    return principal.substring(offset1).trim();
			}
			offset1++;
			if (offset1 >= principal.length()) {
			    return ""; //$NON-NLS-1$
			}

			offset2 = principal.indexOf('"', offset1);
			if (offset2 == offset1) {
			    return ""; //$NON-NLS-1$
			}
			if (offset2 != -1) {
			    return principal.substring(offset1, offset2);
			}
			return principal.substring(offset1);

        }

        return null;
    }

    /** Identifica si un certificado es de seud&oacute;nimo.
     * @param cert Certificado que hay que comprobar.
     * @return Devuelve {@code true} si es un certificado de seud&oacute;nimo, {@code false} en caso contrario. */
    public static boolean isPseudonymCert(final X509Certificate cert) {
    	// El certificado es de seudonimo si declara la extension 2.5.4.65
    	return getRDNvalueFromLdapName("2.5.4.65", //$NON-NLS-1$
    			cert.getSubjectX500Principal().getName(X500Principal.RFC2253)) != null;
    }

	/** Convierte un objeto de propiedades en una cadena Base64 URL SAFE.
	 * @param p Objeto de propiedades a convertir.
	 * @return Base64 URL SAFE que descodificado es un fichero de propiedades en texto plano.
	 * @throws IOException Si hay problemas en la conversi&oacute;n a Base64. */
	public static String properties2Base64(final Properties p) throws IOException {
		if (p == null) {
			return ""; //$NON-NLS-1$
		}
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		final OutputStreamWriter osw = new OutputStreamWriter(baos, DEFAULT_ENCODING);
		p.store(osw, ""); //$NON-NLS-1$
		return Base64.getEncoder().encodeToString(baos.toByteArray()).replace('+', '-').replace('/', '_');
	}

	/** Convierte una cadena Base64 en un objeto de propiedades.
	 * @param base64 Base64 que descodificado es un fichero de propiedades en texto plano.
	 * @return Objeto de propiedades.
	 * @throws IOException Si hay problemas en el proceso. */
    public static Properties base642Properties(final String base64) throws IOException {
    	final Properties p = new Properties();
    	if (base64 == null || base64.isEmpty()) {
    		return p;
    	}
    	p.load(new InputStreamReader(
			new ByteArrayInputStream(Base64.getDecoder().decode(base64.replace('-', '+').replace('_', '/'))), DEFAULT_ENCODING)
		);

    	return p;
    }

    /** Comprueba si un array de datos es una cadena en Base64.
     * @param data Datos a comprobar si podr&iacute;an o no ser Base64.
     * @return <code>true</code> si los datos proporcionado pueden ser una
     *         codificaci&oacute;n Base64 de un original binario (que no tiene
     *         necesariamente porqu&eacute; serlo), <code>false</code> en caso contrario. */
    public static boolean isBase64(final byte[] data) {

        int count = 0;

        // Comprobamos que todos los caracteres de la cadena pertenezcan al alfabeto Base64

        for (int i = 0; i < data.length; i++) {
        	final char b = (char) data[i];
        	// Solo puede aparecer el signo igual en los dos ultimos caracteres de la cadena
        	if (BASE_64_ALPHABET.indexOf(b) == -1 || b == '=' && i < data.length - 2) {
        		return false;
        	}
        	if (b != '\n' && b != '\r') {
        		count++;
        	}
        }

        // Comprobamos que la cadena (sin contar los saltos de linea) tenga una longitud multiplo de 4 caracteres
        return count % 4 == 0;
    }

    /** Comprueba si una cadena de texto es una cadena en Base64.
     * @param data Cadena de texto a comprobar si podr&iacute;an o no ser Base64.
     * @return <code>true</code> si los datos proporcionado pueden ser una
     *         codificaci&oacute;n Base64 de un original binario (que no tiene
     *         necesariamente porqu&eacute; serlo), <code>false</code> en caso contrario. */
    public static boolean isBase64(final String data) {

        int count = 0;

        // Comprobamos que todos los caracteres de la cadena pertenezcan al alfabeto Base64

        for (int i = 0; i < data.length(); i++) {
        	final char b = data.charAt(i);
        	// Solo puede aparecer el signo igual en como 2 ultimos caracteres de la cadena
        	if (BASE_64_ALPHABET.indexOf(b) == -1 || b == '=' && i < data.length() - 2) {
        		return false;
        	}
        	if (b != '\n' && b != '\r') {
        		count++;
        	}
        }

        // Comprobamos que la cadena (sin contar los saltos de linea) tenga una longitud multiplo de 4 caracteres
        return count % 4 == 0;
    }
}
