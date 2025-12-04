package es.gob.afirma.standalone.ui.tasks;

import java.util.logging.Logger;

import javax.security.auth.callback.PasswordCallback;
import javax.swing.SwingUtilities;

import es.gob.afirma.core.misc.Platform;
import es.gob.afirma.core.prefs.KeyStorePreferencesManager;
import es.gob.afirma.keystores.AOKeyStore;
import es.gob.afirma.keystores.AOKeyStoreManager;
import es.gob.afirma.keystores.AOKeyStoreManagerFactory;
import es.gob.afirma.standalone.SimpleAfirmaMessages;
import es.gob.afirma.standalone.SimpleKeyStoreManager;
import es.gob.afirma.standalone.configurator.common.PreferencesManager;
import es.gob.afirma.standalone.ui.ProgressInfoDialogManager;

public class LoadKeystoreTask extends Thread{
	
	private static final Logger LOGGER = Logger.getLogger("es.gob.afirma"); //$NON-NLS-1$
	
	private AOKeyStoreManager ksm;
	
	private AOKeyStore aoks;
	
	private Exception e;

    @Override
    public void run() {
    	
    	LOGGER.info("Iniciando hilo para la carga de almacen: "); //$NON-NLS-1$
    	
    	SwingUtilities.invokeLater(() -> {
    		ProgressInfoDialogManager.showProgressDialog(SimpleAfirmaMessages.getString("ProgressInfoDialog.2")); //$NON-NLS-1$
    	});
    	
    	try {
    		
    		final String lastSelectedKeyStore = KeyStorePreferencesManager.getLastSelectedKeystore();
    		final boolean useDefaultStore = PreferencesManager.getBoolean(PreferencesManager.PREFERENCE_USE_DEFAULT_STORE_IN_BROWSER_CALLS);

    		// Si hay marcado un almacen como el ultimo seleccionado, lo usamos (este es el caso en el que se llaman
    		// varias operaciones de firma dentro de la misma invocacion a la aplicacion)
    		if (lastSelectedKeyStore != null && !lastSelectedKeyStore.isEmpty()) {
    			this.aoks = SimpleKeyStoreManager.getLastSelectedKeystore();
    		}
    		// Si no, si el usuario definio un almacen por defecto para usarlo en las llamadas a la aplicacion, lo usamos
    		else if (useDefaultStore) {
    			final String defaultStore = PreferencesManager.get(PreferencesManager.PREFERENCE_KEYSTORE_DEFAULT_STORE);
    			if (!PreferencesManager.VALUE_KEYSTORE_DEFAULT.equals(defaultStore) 
    				&& !AOKeyStore.PKCS12.getName().equals(defaultStore) 
    				&& !AOKeyStore.PKCS11.getName().equals(defaultStore)) {
    				this.aoks = SimpleKeyStoreManager.getKeyStore(defaultStore, true);
    			}
    		}

    		// Si aun no se ha definido el almacen, se usara el por defecto para el sistema operativo
    		if (this.aoks == null || !isOsKeyStore(this.aoks)) {
    			this.aoks = AOKeyStore.getDefaultKeyStoreTypeByOs(Platform.getOS());
    		}
    		
    		final PasswordCallback pwc = this.aoks.getStorePasswordCallback(null);
    		
    		this.ksm = AOKeyStoreManagerFactory.getAOKeyStoreManager(this.aoks, // Store
					null, // Lib
					null, // Description
					pwc, // PasswordCallback
					null // Parent
					);

    	} catch (final Exception e) {
    		LOGGER.severe("Error al cargar almacen de claves :" + e); //$NON-NLS-1$ 
    		this.e = e;
    	}
    	
    	ProgressInfoDialogManager.hideProgressDialog();
    	
    }

	public AOKeyStoreManager getKeyStoreManager() {
		return this.ksm;
	}
	
	public AOKeyStore getAOKeyStore() {
		return this.aoks;
	}

	public Exception getException() {
		return this.e;
	}
	
	/**
	 * Devuelve true si es un almac&eacute;n que pertenece a alg&uacute;n sistema operativo.
	 * @param aoks Almac&eacute;n a comprobar.
	 * @return true en caso de que pertenezca a un sistema operativo, false en caso contrario.
	 */
    public static boolean isOsKeyStore(final AOKeyStore aoks) {
		if (AOKeyStore.WINDOWS.equals(aoks) 
			|| AOKeyStore.APPLE.equals(aoks) 
			|| AOKeyStore.SHARED_NSS.equals(aoks) 
			|| AOKeyStore.MOZ_UNI.equals(aoks)) {
			return true;
		}
		return false;
    }

}
