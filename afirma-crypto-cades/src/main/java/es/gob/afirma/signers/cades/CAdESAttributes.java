package es.gob.afirma.signers.cades;

final class CAdESAttributes {

	private CAdESAttributes() {
		// No instanciable
	}

	/**
	 * Identificador del id-aa-ets-signerAttrV2. Esta propiedad se utiliza para indicar
	 * los roles en las firmas baseline ETSI EN 319 122-1.
	 */
	static final String oidIdAaEtsSignerAttrV2 =  "0.4.0.19122.1.1"; //$NON-NLS-1$

    /**
	 * Identificador del id-aa-ets-mimeType. Esta propiedad se utiliza para incluir el MimeType
	 * de los datos en la firma. Definido por primera vez en ETSI TS 101 733 V2.1.1 (2012-03).
	 */
    static final String oidIdAaEtsMimeType =  "0.4.0.1733.2.1"; //$NON-NLS-1$
}
