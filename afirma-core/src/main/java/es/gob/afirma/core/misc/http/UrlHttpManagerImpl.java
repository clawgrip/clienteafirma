/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.core.misc.http;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Properties;
import java.util.StringTokenizer;

import es.gob.afirma.core.misc.AOUtil;

/** Clase para la lectura y env&iacute;o de datos a URL remotas.
 * @author Carlos Gamuci.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public class UrlHttpManagerImpl implements UrlHttpManager {

	/** Nombre de la propiedad a establecer a <code>true</code> para deshabilitar las comprobaciones
	 * de confianza SSL en las peticiones. Si se establece a <code>false</code> o no se establece se
	 * usa la confianza por defecto de la JVM. */
	public static final String JAVA_PARAM_DISABLE_SSL_CHECKS = "disableSslChecks"; //$NON-NLS-1$

	/** Lista de dominios seguros para conexiones HTTPS. */
	public static final String JAVA_PARAM_SECURE_DOMAINS_LIST = "secureDomainsList"; //$NON-NLS-1$

	/** Tiempo de espera por defecto para descartar una conexi&oacute;n HTTP. */
	public static final int DEFAULT_TIMEOUT = -1;

	private static final String URN_SEPARATOR = ":"; //$NON-NLS-1$
	private static final String PROT_SEPARATOR = URN_SEPARATOR + "//"; //$NON-NLS-1$

	private static final String ACCEPT = "Accept"; //$NON-NLS-1$

	static {
		final CookieManager cookieManager = new CookieManager();
		cookieManager.setCookiePolicy(CookiePolicy.ACCEPT_ALL);
		CookieHandler.setDefault(cookieManager);
	}

	/** Constructor. */
	protected UrlHttpManagerImpl() {
		// Vacio y "protected"
	}

	@Override
	public byte[] readUrl(final String url, final UrlHttpMethod method) throws IOException {
		return readUrl(url, DEFAULT_TIMEOUT, null, null, method);
	}

	@Override
	public byte[] readUrl(final String urlToRead,
			              final int timeout,
			              final String contentType,
			              final String accept,
			              final UrlHttpMethod method) throws IOException {
		final Properties headers = buildHeaders(contentType, accept);
		return readUrl(urlToRead, timeout, method, headers);
	}

	private static Properties buildHeaders(final String contentType, final String accept) {
		final Properties headers = new Properties();
		if (contentType != null) {
			headers.setProperty("Content-Type", contentType); //$NON-NLS-1$
		}
		if (accept != null) {
			headers.setProperty(ACCEPT, accept);
		}
		return headers;
	}

	@Override
	public byte[] readUrl(final String urlToRead,
	                      final int timeout,
		                  final UrlHttpMethod method,
		                  final Properties requestProperties) throws IOException {

		if (urlToRead == null) {
			throw new IllegalArgumentException("La URL a leer no puede ser nula"); //$NON-NLS-1$
		}

		// Vemos si lleva usuario y contrasena
		final String authString;
		final String url;
		final URLName un = new URLName(urlToRead);

		if (un.getUsername() != null || un.getPassword() != null) {
			final String tmpStr;
			if (un.getUsername() != null && un.getPassword() != null) {
				tmpStr = un.getUsername() + URN_SEPARATOR + un.getPassword();
			}
			else if (un.getUsername() != null) {
				tmpStr = un.getUsername();
			}
			else {
				tmpStr = un.getPassword();
			}
			authString = Base64.getEncoder().encodeToString(tmpStr.getBytes());
			url = un.getProtocol() +
				PROT_SEPARATOR +
					un.getHost() +
						(un.getPort() != -1 ? URN_SEPARATOR +
							Integer.toString(un.getPort()) : "") + //$NON-NLS-1$
								"/" + //$NON-NLS-1$
									(un.getFile() != null ? un.getFile() : ""); //$NON-NLS-1$
		}
		else {
			url = urlToRead;
			authString = null;
		}

		String urlParameters = null;
		String request = null;
		if (UrlHttpMethod.POST.equals(method) || UrlHttpMethod.PUT.equals(method)) {
			final StringTokenizer st = new StringTokenizer(url, "?"); //$NON-NLS-1$
			request = st.nextToken();
			if (url.contains("?")) { //$NON-NLS-1$
				urlParameters = st.nextToken();
			}
		}

		final URL uri = new URL(request != null ? request : url);

		final HttpURLConnection conn = (HttpURLConnection) uri.openConnection();

		conn.setUseCaches(false);
		conn.setDefaultUseCaches(false);

		conn.setRequestMethod(method.toString());

		// Agregamos a la cabecera del request todas las propiedades indicadas, ademas de los valores
		// por defecto para aquellas imprescindibles para las que no se haya indicado valor

		final Properties headers = new Properties();
		if (requestProperties != null) {
			headers.putAll(requestProperties);
		}

		if (authString != null && !headers.containsKey("Authorization")) { //$NON-NLS-1$
			conn.addRequestProperty("Authorization", "Basic " + authString); //$NON-NLS-1$ //$NON-NLS-2$
		}
		if (!headers.containsKey(ACCEPT)) {
			conn.addRequestProperty(ACCEPT, "*/*"); //$NON-NLS-1$
		}
		if (!headers.containsKey("Connection")) { //$NON-NLS-1$
			conn.addRequestProperty("Connection", "keep-alive"); //$NON-NLS-1$ //$NON-NLS-2$
		}
		if (!headers.containsKey("Host")) { //$NON-NLS-1$
			conn.addRequestProperty("Host", uri.getHost()); //$NON-NLS-1$
		}
		if (!headers.containsKey("Origin")) { //$NON-NLS-1$
			conn.addRequestProperty("Origin", uri.getProtocol() +  "://" + uri.getHost()); //$NON-NLS-1$ //$NON-NLS-2$
		}

		// Ponemos el resto de las cabeceras
		for (final Map.Entry<?, ?> entry : headers.entrySet()) {
			conn.addRequestProperty((String) entry.getKey(), (String) entry.getValue());
		}

		if (urlParameters != null) {
			conn.setRequestProperty(
				"Content-Length", String.valueOf(urlParameters.getBytes(StandardCharsets.UTF_8).length) //$NON-NLS-1$
			);
			conn.setDoOutput(true);
			try (OutputStream os = conn.getOutputStream()) {
				os.write(urlParameters.getBytes(StandardCharsets.UTF_8));
			}
		}

		// Si se ha establecido un tiempo de timeout, se configura como tiempo maximo hasta la conexion
		if (timeout != DEFAULT_TIMEOUT) {
			conn.setConnectTimeout(timeout);
		}

		conn.connect();
		final int resCode = conn.getResponseCode();
		final String statusCode = Integer.toString(resCode);
		if (statusCode.startsWith("4") || statusCode.startsWith("5")) { //$NON-NLS-1$ //$NON-NLS-2$
			try (InputStream errorStream = conn.getErrorStream()) {
				throw new HttpError(
					resCode,
					conn.getResponseMessage(),
					AOUtil.getDataFromInputStream(errorStream),
					url
				);
			}
		}

		try (final InputStream is = conn.getInputStream()) {
			return AOUtil.getDataFromInputStream(is);
		}
	}
}