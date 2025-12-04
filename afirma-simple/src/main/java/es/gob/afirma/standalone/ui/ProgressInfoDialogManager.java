/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.standalone.ui;

/** Clase que gestiona los mensajes mostrados por el di&aacute;logo de progreso
 * y que muestra o esconde el di&aacute;logo.*/

public final class ProgressInfoDialogManager {

	private static ProgressInfoDialog infoDialog;
	
	private static boolean showProgressDialog;
	
	public static void init(boolean showProgressDialogParam) {
		showProgressDialog = showProgressDialogParam;
	}
	
	/** Elimina el di&aacute;logo de la vista 
	 * @param message Mensaje del di&aacute;logo. */
	public static void showProgressDialog(final String message) {
		
	    if (!showProgressDialog) {
			return;
		}

	    if (infoDialog == null || !infoDialog.isEnabledDialog()) {
	        infoDialog = new ProgressInfoDialog(null);
	    }

	    infoDialog.setMessage(message);
	    infoDialog.setVisible(true);
	}

	/** Elimina el di&aacute;logo de la vista */
	public static void hideProgressDialog() {
		if (infoDialog != null) {
			infoDialog.setVisible(false);
		}	
	}

}
