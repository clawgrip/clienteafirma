/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.signers.tsp.pkcs7;

import java.net.URI;
import java.util.Base64;
import java.util.Properties;
import java.util.logging.Logger;

import es.gob.afirma.core.signers.AOSignConstants;

/** Par&aacute;metros de configuraci&oacute;n de una Autoridad de Sellado de Tiempo.
 * @author Tomas Garc&iacute;a-Mer&aacute;s. */
public final class TsaParams {

	private static final String DEFAULT_DIGEST_ALGO = "SHA-256"; //$NON-NLS-1$

	/** Sello de tiempo a nivel de firma. */
	public static final String TS_SIGN = "1";  //$NON-NLS-1$

	/** Sello de tiempo a nivel de documento. */
	public static final String TS_DOC = "2";  //$NON-NLS-1$

	/** Sello de tiempo doble, a nivel de firma y a nivel de documento. */
	public static final String TS_SIGN_DOC = "3";  //$NON-NLS-1$

	private static final String PARAM_TSA_POLICY = "tsaPolicy"; //$NON-NLS-1$
	private static final String PARAM_TSA_HASH_ALGORITHM = "tsaHashAlgorithm"; //$NON-NLS-1$

	private final boolean tsaRequireCert;
	private final String tsaPolicy;
	private final URI tsaURL;
	private final String tsaUsr;
	private final String tsaPwd;
	private final TsaRequestExtension[] extensions;
	private final String tsaHashAlgorithm;

	private static final Logger LOGGER = Logger.getLogger(TsaParams.class.getName());

	/** Construye los par&aacute;metros de configuraci&oacute;n de una Autoridad de Sellado de Tiempo.
	 * @param requireCert Indicar <code>true</code> si es necesario incluir el certificado de la TSA,
	 *                    <code>false</code> en caso contrario.
	 * @param policy OID de la pol&iacute;tica de sellado de tiempo.
	 * @param url URL de la TSA.
	 * @param usr Nombre de usuario para la TSA.
	 * @param pwd Contrase&ntilde;a para el usuario de la TSA.
	 * @param exts Extensiones de la petici&oacute;n a la TSA.
	 * @param hashAlgorithm Algoritmo de huella digital a usar. */
	public TsaParams(final boolean requireCert,
			         final String policy,
			         final URI url,
			         final String usr,
			         final String pwd,
			         final TsaRequestExtension[] exts,
			         final String hashAlgorithm) {
        if (url == null) {
        	throw new IllegalArgumentException("La URL del servidor de sello de tiempo no puede ser nula"); //$NON-NLS-1$
        }
        this.tsaURL = url;
        this.tsaPolicy = policy;
        this.tsaUsr = usr;
        this.tsaPwd = pwd;
        this.extensions = exts != null ? exts.clone() : null;
        this.tsaHashAlgorithm = hashAlgorithm != null ? hashAlgorithm : DEFAULT_DIGEST_ALGO;
        this.tsaRequireCert = requireCert;
	}

	/** Construye los par&aacute;metros de configuraci&oacute;n de una Autoridad de Sellado de Tiempo.
	 * En caso de ausencia o error en las propiedades de entrada lanza una <code>IllegalArgumentException</code>.
	 * @param extraParams Propiedades que contienen los par&aacute;metros de configuraci&oacute;n necesarios. */
	public TsaParams(final Properties extraParams) {
		if (extraParams == null) {
			throw new IllegalArgumentException("La propiedades de configuracion de la TSA no pueden ser nulas"); //$NON-NLS-1$
		}
		final String tsa = extraParams.getProperty("tsaURL"); //$NON-NLS-1$
        if (tsa == null) {
        	throw new IllegalArgumentException("La URL del servidor de sello de tiempo no puede ser nula"); //$NON-NLS-1$
        }
        try {
    		this.tsaURL = new URI(tsa);
    	}
    	catch(final Exception e) {
    		throw new IllegalArgumentException("Se ha indicado una URL de TSA invalida: " + tsa, e); //$NON-NLS-1$
    	}

        this.tsaPolicy = extraParams.containsKey(PARAM_TSA_POLICY) ?
    		extraParams.getProperty(PARAM_TSA_POLICY) :
    			null;

        this.tsaHashAlgorithm = extraParams.containsKey(PARAM_TSA_HASH_ALGORITHM) ?
    		AOSignConstants.getDigestAlgorithmName(extraParams.getProperty(PARAM_TSA_HASH_ALGORITHM)) :
    			DEFAULT_DIGEST_ALGO;

        this.tsaRequireCert = !Boolean.FALSE.toString().equalsIgnoreCase(extraParams.getProperty("tsaRequireCert")); //$NON-NLS-1$
        this.tsaUsr = extraParams.getProperty("tsaUsr"); //$NON-NLS-1$
        this.tsaPwd = extraParams.getProperty("tsaPwd"); //$NON-NLS-1$
        this.extensions = getExtensions(extraParams);
	}

	boolean doTsaRequireCert() {
		return this.tsaRequireCert;
	}

	String getTsaPolicy() {
		return this.tsaPolicy;
	}

	/** Obtiene la URL de la TSA.
	 * @return URL de la TSA. */
	public URI getTsaUrl() {
		return this.tsaURL;
	}

	String getTsaUsr() {
		return this.tsaUsr;
	}

	String getTsaPwd() {
		return this.tsaPwd;
	}

	TsaRequestExtension[] getExtensions() {
		return this.extensions;
	}

	/** Obtiene el listado de extensiones configuradas.
	 * @param config Configuraci&oacute;n en la que se pueden haber declarado las extensiones.
	 * @return Listado de extensiones. */
	private static TsaRequestExtension[] getExtensions(final Properties config) {

		final String extensionOid = config.getProperty("tsaExtensionOid"); //$NON-NLS-1$
		final String extensionValueBase64 = config.getProperty("tsaExtensionValueBase64"); //$NON-NLS-1$
		final boolean extensionCritical = Boolean.parseBoolean(config.getProperty("tsaExtensionCritical", Boolean.FALSE.toString())); //$NON-NLS-1$

		if (extensionOid == null && extensionValueBase64 == null) {
			return null;
		}
		if (extensionOid != null && extensionValueBase64 == null) {
			LOGGER.warning("Se ignorara el parametro 'tsaExtensionOid' ya que no se configuro el parametro 'tsaExtensionValueBase64'"); //$NON-NLS-1$
			return null;
		}
		if (extensionOid == null) {
			LOGGER.warning("Se ignorara el parametro 'tsaExtensionValueBase64' ya que no se configuro el parametro 'tsaExtensionOid'"); //$NON-NLS-1$
			return null;
		}

		return new TsaRequestExtension[] {
			new TsaRequestExtension(
				extensionOid,
				extensionCritical,
				Base64.getDecoder().decode(extensionValueBase64)
			)
		};
	}

	/** Obtiene el algoritmo de huella digital a usar en el sellado de tiempo.
	 * @return Algoritmo de huella digital a usar en el sellado de tiempo. */
	public String getTsaHashAlgorithm() {
		return this.tsaHashAlgorithm;
	}

	/** Obtiene los par&aacute;metros adicionales de la configuraci&oacute;n de una Autoridad de Sellado de Tiempo.
	 * @return Par&aacute;metros adicionales de la configuraci&oacute;n de una Autoridad de Sellado de Tiempo. */
	public Properties getExtraParams() {
		final Properties p = new Properties();
		if (getTsaUrl() != null) {
			p.put("tsaURL", getTsaUrl().toString()); //$NON-NLS-1$
		}
		if (getTsaUsr() != null && !getTsaUsr().isEmpty()) {
			p.put("tsaUsr", getTsaUsr()); //$NON-NLS-1$
		}
		if (getTsaPwd() != null && !getTsaPwd().isEmpty()) {
			p.put("tsaPwd", getTsaPwd()); //$NON-NLS-1$
		}
		if (getTsaPolicy() != null && !getTsaPolicy().isEmpty()) {
			p.put(PARAM_TSA_POLICY, getTsaPolicy());
		}
		if (getExtensions() != null && getExtensions().length > 0) {
			p.put("tsaExtensionOid", getExtensions()[0].getOid()); //$NON-NLS-1$
			p.put("tsaExtensionValueBase64", Base64.getEncoder().encodeToString(getExtensions()[0].getValue())); //$NON-NLS-1$
			p.put("tsaExtensionCritical", Boolean.toString(getExtensions()[0].isCritical())); //$NON-NLS-1$
		}
		if (getTsaHashAlgorithm() != null && !getTsaHashAlgorithm().isEmpty()) {
			p.put(PARAM_TSA_HASH_ALGORITHM, getTsaHashAlgorithm());
		}
		return p;
	}

	@Override
	public String toString() {

		// Extensiones
		final StringBuilder exts = new StringBuilder("["); //$NON-NLS-1$
		if (this.extensions != null) {
			for(final TsaRequestExtension ex : this.extensions) {
				exts.append(ex)
				    .append("; "); //$NON-NLS-1$
			}
		}
		exts.append("]"); //$NON-NLS-1$

		final String ret = "Parametros TSA [" + //$NON-NLS-1$
			"URL=" + getTsaUrl() + "; " + //$NON-NLS-1$ //$NON-NLS-2$
				"User=" + getTsaUsr() + ": " + //$NON-NLS-1$ //$NON-NLS-2$
				"Policy=" + getTsaPolicy() + "; " + //$NON-NLS-1$ //$NON-NLS-2$
				"Extensions" + exts.toString() + "; " + //$NON-NLS-1$ //$NON-NLS-2$
				"Digest=" + getTsaHashAlgorithm() + "; " + //$NON-NLS-1$ //$NON-NLS-2$
			"]"; //$NON-NLS-1$

		// Quitamos el punto y coma de la ultima extension
		return ret.replace("]; ]", "]]"); //$NON-NLS-1$ //$NON-NLS-2$
	}
}
