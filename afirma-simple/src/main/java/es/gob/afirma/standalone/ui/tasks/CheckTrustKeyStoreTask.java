package es.gob.afirma.standalone.ui.tasks;

import java.io.File;
import java.util.logging.Logger;

import javax.swing.JOptionPane;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.ui.AOUIFactory;
import es.gob.afirma.standalone.SimpleAfirmaMessages;
import es.gob.afirma.standalone.SimpleErrorCode;
import es.gob.afirma.standalone.protocol.SecureSocketUtils;

public class CheckTrustKeyStoreTask extends Thread{
	
	private static final Logger LOGGER = Logger.getLogger("es.gob.afirma"); //$NON-NLS-1$

    @Override
    public void run() {

    	LOGGER.info("Iniciando hilo para la comprobacion de la correcta instalacion del almacen de confianza: "); //$NON-NLS-1$  

		final File trustedKeyStoreFile = SecureSocketUtils.getKeyStoreFile();

		// Si no encontramos el almacen de confianza de Autofirma, no modificamos
		// la configuracion SSL
		if (trustedKeyStoreFile == null || !trustedKeyStoreFile.exists() || !trustedKeyStoreFile.isFile()) {
			AOUIFactory.showErrorMessage(
					null,
					SimpleAfirmaMessages.getString("TrustedKeyStoreError.0"), //$NON-NLS-1$
					SimpleAfirmaMessages.getString("SimpleAfirma.7"), //$NON-NLS-1$
					JOptionPane.ERROR_MESSAGE,
					new AOException(SimpleErrorCode.Internal.TRUSTSTORE_INCORRECT_INSTALLATION));
		}
    	
    }
	
}
