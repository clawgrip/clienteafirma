/* Copyright (C) 2019 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.standalone.protocol;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLContext;
import javax.swing.JOptionPane;

import org.java_websocket.server.DefaultSSLWebSocketServerFactory;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.misc.protocol.ProtocolVersion;
import es.gob.afirma.core.ui.AOUIFactory;
import es.gob.afirma.standalone.SimpleAfirmaMessages;
import es.gob.afirma.standalone.SimpleErrorCode;
import es.gob.afirma.standalone.configurator.common.PreferencesManager;

/** Gestor de la invocaci&oacute;n por <i>WebSocket</i>. */
public class AfirmaWebSocketServerManager {

	static final Logger LOGGER = Logger.getLogger("es.gob.afirma"); //$NON-NLS-1$

	/** Versi&oacute;n de protocolo en la que el puerto de conexi&oacute;n era fijo. */
	private static final int PROTOCOL_VERSION_3 = 3;

	/** Versi&oacute;n de protocolo con varios puertos y comprobaci&oacute;n de ID de sesi&oacute;n. */
	private static final int PROTOCOL_VERSION_4 = 4;

	/** Versi&oacute;n de protocolo actual. */
	private static final int CURRENT_PROTOCOL_VERSION = PROTOCOL_VERSION_4;

	/** Listado de versiones de protocolo soportadas. */
	private static final int[] SUPPORTED_PROTOCOL_VERSIONS = new int[] { PROTOCOL_VERSION_3, PROTOCOL_VERSION_4 };

    /** Propiedad del sistema para configurar la optimizacion de WebSockets para VDI. */
	private static final String SYSTEM_PROPERTY_OPTIMIZED_FOR_VDI = "websockets.optimizedForVdi"; //$NON-NLS-1$

	static AfirmaWebSocketServer instance = null;

	/**
	 * Inicia un WebSocket para la comunicaci&oacute;n con el navegador.
	 * @param channelInfo Informaci&oacute;n para la construcci&oacute;n de la comunicaci&oacute;n.
	 * @param requestedProtocolVersion Versi&oacute;n del protocolo de comunicaci&oacute;n.
	 * @param asynchronous Si viene con valor <code>true</code> tratar&aacute; las operaciones de forma as&iacute;ncrona si viene a false las tratara como s&iacute;ncronas<code>false</code>.
	 * @throws UnsupportedProtocolException Cuando se ha solicitado el uso de una versi&oacute;n de protocolo no soportada.
	 * @throws SocketOperationException Cuando
	 */
	public static void startService(final ChannelInfo channelInfo, final ProtocolVersion requestedProtocolVersion, final boolean asynchronous) throws UnsupportedProtocolException, SocketOperationException {

		checkSupportProtocol(requestedProtocolVersion);
		
    	// Si al intentar obtener el contexto SSL, se recibe alguna excepcion, se mostrar el error
    	try {
    		SecureSocketUtils.getSecureSSLContext();
    	} catch (Exception e) {
			LOGGER.severe("No se ha encontrado el almacen de claves de Autofirma"); //$NON-NLS-1$
			AOUIFactory.showErrorMessage(
					null,
					SimpleAfirmaMessages.getString("TrustedKeyStoreError.0"), //$NON-NLS-1$
					SimpleAfirmaMessages.getString("SimpleAfirma.7"), //$NON-NLS-1$
					JOptionPane.ERROR_MESSAGE,
					new AOException(SimpleErrorCode.Internal.TRUSTSTORE_INCORRECT_INSTALLATION));
			ProtocolInvocationLauncher.forceCloseApplication(0);
    	}

 		// Configuramos la optimizacion para VDI segun lo establecido en el dialogo de preferencias
 		final boolean optimizedForVdi = PreferencesManager
 				.getBoolean(PreferencesManager.PREFERENCE_GENERAL_VDI_OPTIMIZATION);
         System.setProperty(SYSTEM_PROPERTY_OPTIMIZED_FOR_VDI, Boolean.toString(optimizedForVdi));

		int i = 0;
		final int[] ports = channelInfo.getPorts();
		do {
			LOGGER.info("Tratamos de abrir el socket en el puerto: " + ports[i]); //$NON-NLS-1$

			try {
				switch (requestedProtocolVersion.getMajorVersion()) {
				case PROTOCOL_VERSION_4:
					instance = new AfirmaWebSocketServerV4Sup(ports[i], channelInfo.getIdSession(), requestedProtocolVersion);
					((AfirmaWebSocketServerV4Sup) instance).setAsyncOperation(asynchronous);
					break;

				default:
					instance = new AfirmaWebSocketServer(ports[i], channelInfo.getIdSession());
					break;
				}

				final SSLContext sc = SecureSocketUtils.getSecureSSLContext();
				instance.setWebSocketFactory(new DefaultSSLWebSocketServerFactory(sc));
				instance.start();
			}
			catch (final Exception e) {
				LOGGER.log(Level.WARNING, "No se ha podido abrir un socket en el puerto: " + ports[i], e); //$NON-NLS-1$
				instance = null;
			}
			i++;
		}
		while (instance == null && i < ports.length);

		if (instance == null) {
			throw new SocketOperationException("No se ha podido abrir ningun socket. Se aborta la comunicacion.", SimpleErrorCode.Internal.SOCKET_INITIALIZING_ERROR); //$NON-NLS-1$
		}
	}

	/** Comprueba si una versi&oacute;n de protocolo est&aacute; soportado por la implementaci&oacute;n actual.
	 * @param version Identificador de la versi&oacute;n del protocolo.
	 * @throws UnsupportedProtocolException Cuando la versi&oacute;n de protocolo utilizada no se encuentra
	 *                                      entre las soportadas. */
	private static void checkSupportProtocol(final ProtocolVersion requestversion) throws UnsupportedProtocolException {
		for (final int supportedVersion : SUPPORTED_PROTOCOL_VERSIONS) {
			if (supportedVersion == requestversion.getMajorVersion()) {
				return;
			}
		}
		throw new UnsupportedProtocolException(requestversion, requestversion.getMajorVersion() > CURRENT_PROTOCOL_VERSION);
	}

}
