package es.gob.afirma.standalone.protocol;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.java_websocket.WebSocket;

public class WebSocketServerOperationHandler {
	
	static final Logger LOGGER = Logger.getLogger("es.gob.afirma"); //$NON-NLS-1$
	
	private static final String WAIT_RESPONSE = "#wait"; //$NON-NLS-1$
	
	/** Par&aacute;metro de entrada con el identificador del documento. */
	private static final String IDSESSION_PARAM = "idsession"; //$NON-NLS-1$
	
	private static final String GET_RESULT_URL = "getresult?"; //$NON-NLS-1$
	
	public static void handleOperation(final int protocol, final String operation, 
			final String sessionId, final AfirmaWebSocketServerV4SupAsync server, final WebSocket ws) {
		
		if(operation.startsWith(GET_RESULT_URL)) {
			getResultAndSendResponse(operation, server, ws);			
		} else {
			
			try {
				final ActiveWebSocketOperationThread activeWebSocketWaitingThread 
				= new ActiveWebSocketOperationThread(protocol, operation, sessionId);
				
	    		activeWebSocketWaitingThread.start();
	    		AfirmaWebSocketServerManager.waitingThreadMap.put(sessionId, activeWebSocketWaitingThread);
	    		server.broadcast(WAIT_RESPONSE, Collections.singletonList(ws));
			} catch (final Exception e) {
				LOGGER.warning("Error al procesar la operacion: " + operation + "\n" + e); //$NON-NLS-1$ //$NON-NLS-2$
			}
			
		}
	}
	
	private static void getResultAndSendResponse(final String operation, final AfirmaWebSocketServerV4SupAsync server, final WebSocket ws) {
		
    	final Map<String, String> params = extractParams(operation);
		final String sessionId = params.get(IDSESSION_PARAM);
		
		// Comprobamos si el hilo de espera activa sigue en ejecucion o ya ha terminado la operacion
		final ActiveWebSocketOperationThread websocketOperationThread = AfirmaWebSocketServerManager.waitingThreadMap.get(sessionId);
		
		if (websocketOperationThread == null) {
			LOGGER.warning("No se ha iniciado una sesion para el id: " + sessionId); //$NON-NLS-1$
			server.broadcast(WAIT_RESPONSE, Collections.singletonList(ws));
		} else if (websocketOperationThread.isAlive()) {
			// Se devuelve respuesta de espera al socket, la operacion no ha terminado
			LOGGER.info("El hilo con la operacion sigue ejecutandose para la sesion: " + sessionId); //$NON-NLS-1$
			server.broadcast(WAIT_RESPONSE, Collections.singletonList(ws));
		} else {
			// La operacion ha terminado y devolvemos su resultado
			LOGGER.info("Se devuelve el resultado para la sesion: " + sessionId); //$NON-NLS-1$
			final String result = websocketOperationThread.getOperationResult(); 
			server.broadcast(result, Collections.singletonList(ws));
			AfirmaWebSocketServerManager.waitingThreadMap.remove(sessionId);		
		}
	}
	
	/**
	 * Extrae los parametros declarados en una URL con sus valores asignados.
	 * @param url URL de la que extraer los par&aacute;metros.
	 * @return Conjunto de par&aacute;metros con sus valores.
	 */
	private static Map<String, String> extractParams(final String url) {

		final Map<String, String> params = new HashMap<>();

		final int initPos = url.indexOf('?') + 1;
		final String[] urlParams = url.substring(initPos).split("&"); //$NON-NLS-1$
		for (final String param : urlParams) {
			final int equalsPos = param.indexOf('=');
			if (equalsPos > 0) {
				try {
					params.put(
							param.substring(0, equalsPos),
							URLDecoder.decode(param.substring(equalsPos + 1), StandardCharsets.UTF_8.toString()));
				} catch (final UnsupportedEncodingException e) {
					LOGGER.warning("No se pudo decodificar el valor del parametro '" + param.substring(0, equalsPos) + "': " + e); //$NON-NLS-1$ //$NON-NLS-2$
				}
			}
		}

		return params;
	}

}
