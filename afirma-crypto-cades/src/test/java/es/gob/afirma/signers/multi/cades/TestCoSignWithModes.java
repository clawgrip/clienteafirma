/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.signers.multi.cades;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.Arrays;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.core.signers.AOSigner;
import es.gob.afirma.core.signers.AOSimpleSignInfo;
import es.gob.afirma.core.util.tree.AOTreeModel;
import es.gob.afirma.core.util.tree.AOTreeNode;
import es.gob.afirma.signers.cades.AOCAdESSigner;
import es.gob.afirma.signers.pkcs7.ContainsNoDataException;

/** Pruebas de cofirmas CAdES. */
class TestCoSignWithModes {

	private static final Logger LOGGER = Logger.getLogger("es.gob.afirma"); //$NON-NLS-1$

    private static final String CERT_PATH_TO_SIGN = "PruebaEmpleado4Activo.p12"; //$NON-NLS-1$
    private static final String CERT_PASS_TO_SIGN = "Giss2016"; //$NON-NLS-1$
    private static final String CERT_ALIAS_TO_SIGN = "givenname=prueba4empn+serialnumber=idces-00000000t+sn=p4empape1 p4empape2 - 00000000t+cn=prueba4empn p4empape1 p4empape2 - 00000000t,ou=personales,ou=certificado electronico de empleado publico,o=secretaria de estado de la seguridad social,c=es"; //$NON-NLS-1$

    private static final String CERT_PATH_TO_COSIGN = "00_empleado_publico-hsm.p12"; //$NON-NLS-1$
    private static final String CERT_PASS_TO_COSIGN = "12345"; //$NON-NLS-1$
    private static final String CERT_ALIAS_TO_COSIGN = "nombre apellido1 apellido2 - dni 12345678z"; //$NON-NLS-1$

	private static final String DATA_FILE = "xml"; //$NON-NLS-1$

	private byte[] data;

	private Properties implicitParams;

	private Properties explicitParams;

	private PrivateKeyEntry pke = null;

	private byte[] explicitSHA256Signature = null;

	private byte[] explicitSHA512Signature = null;

	private byte[] implicitSHA256Signature = null;

	private byte[] implicitSHA512Signature = null;

	private AOSigner signer = null;

	/** Antes de ejecutar cualquier prueba se cargan
	 * todos los objetos que se vaya a necesitar en las distintas pruebas.
	 * @throws Exception En cualquier error. */
	@BeforeAll
	void loadParams() throws Exception {

		Logger.getLogger("es.gob.afirma").setLevel(Level.WARNING); //$NON-NLS-1$

		this.implicitParams = new Properties();
		this.implicitParams.setProperty("mode", AOSignConstants.SIGN_MODE_IMPLICIT); //$NON-NLS-1$

		this.explicitParams = new Properties();
		this.explicitParams.setProperty("mode", AOSignConstants.SIGN_MODE_EXPLICIT); //$NON-NLS-1$

		final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
		try (InputStream is = ClassLoader.getSystemResourceAsStream(CERT_PATH_TO_SIGN)) {
			ks.load(is, CERT_PASS_TO_SIGN.toCharArray());
		}
		final PrivateKeyEntry pkeSign = (PrivateKeyEntry) ks.getEntry(CERT_ALIAS_TO_SIGN, new KeyStore.PasswordProtection(CERT_PASS_TO_SIGN.toCharArray()));

		final KeyStore ksCosign = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
		try (InputStream is = ClassLoader.getSystemResourceAsStream(CERT_PATH_TO_COSIGN)) {
			ksCosign.load(is, CERT_PASS_TO_COSIGN.toCharArray());
		}
		this.pke = (PrivateKeyEntry) ksCosign.getEntry(CERT_ALIAS_TO_COSIGN, new KeyStore.PasswordProtection(CERT_PASS_TO_COSIGN.toCharArray()));

		try (InputStream is = TestCoSignWithModes.class.getResourceAsStream("/" + DATA_FILE)) { //$NON-NLS-1$
			this.data = AOUtil.getDataFromInputStream(is);
		}
		catch (final IOException e) {
			LOGGER.log(Level.SEVERE, "No se ha podido cargar el fichero de pruebas: " + DATA_FILE, e);  //$NON-NLS-1$
		}

		this.signer = new AOCAdESSigner();
		this.explicitSHA256Signature = this.signer.sign(this.data, AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA, pkeSign.getPrivateKey(), pkeSign.getCertificateChain(), this.explicitParams);
		this.explicitSHA512Signature = this.signer.sign(this.data, AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA, pkeSign.getPrivateKey(), pkeSign.getCertificateChain(), this.explicitParams);
		this.implicitSHA256Signature = this.signer.sign(this.data, AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA, pkeSign.getPrivateKey(), pkeSign.getCertificateChain(), this.implicitParams);
		this.implicitSHA512Signature = this.signer.sign(this.data, AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA, pkeSign.getPrivateKey(), pkeSign.getCertificateChain(), this.implicitParams);
	}

	/** Cofirma impl&iacute;cita con algoritmo SHA512withRSA sobre firma impl&iacute;cita
	 * con algoritmo de SHA512withRSA.
	 * @throws Exception en cualquier error. */
	@Test
	void testCofirmaImplicitaSHA512SobreFirmaImplicitaSHA512() throws Exception {

		final String algorithm = AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA;

		final byte[] result = this.signer.cosign(
				this.implicitSHA512Signature, algorithm,
				this.pke.getPrivateKey(), this.pke.getCertificateChain(), this.implicitParams);

		final File saveFile = saveTempFile(result);
		System.out.println("Prueba testCofirmaImplicitaSHA512SobreFirmaImplicitaSHA512: " + saveFile.getAbsolutePath()); //$NON-NLS-1$

		checkCosign(result, algorithm, true);
	}

	/** Cofirma expl&iacute;cita con algoritmo SHA512withRSA sobre firma impl&iacute;cita
	 * con algoritmo de SHA512withRSA.
	 * @throws Exception en cualquier error. */
	@Test
	void testCofirmaExplicitaSHA512SobreFirmaImplicitaSHA512() throws Exception {

		final String algorithm = AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA;

		final byte[] result = this.signer.cosign(
				this.implicitSHA512Signature, algorithm,
				this.pke.getPrivateKey(), this.pke.getCertificateChain(), this.explicitParams);

		final File saveFile = saveTempFile(result);
		System.out.println("Prueba testCofirmaExplicitaSHA512SobreFirmaImplicitaSHA512: " + saveFile.getAbsolutePath()); //$NON-NLS-1$

		checkCosign(result, algorithm, true);
	}


	/** Cofirma impl&iacute;cita con algoritmo SHA512withRSA sobre firma expl&iacute;cita
	 * con algoritmo de SHA512withRSA.
	 * @throws Exception en cualquier error. */
	@Test
	void testCofirmaImplicitaSHA512SobreFirmaExplicitaSHA512() throws Exception {

		final String algorithm = AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA;

		final byte[] result = this.signer.cosign(
				this.explicitSHA512Signature, algorithm,
				this.pke.getPrivateKey(), this.pke.getCertificateChain(), this.implicitParams);

		final File saveFile = saveTempFile(result);
		System.out.println("Prueba testCofirmaImplicitaSHA512SobreFirmaExplicitaSHA512: " + saveFile.getAbsolutePath()); //$NON-NLS-1$

		checkCosign(result, algorithm, false);
	}

	/** Cofirma expl&iacute;cita con algoritmo SHA512withRSA sobre firma expl&iacute;cita
	 * con algoritmo de SHA512withRSA.
	 * @throws Exception en cualquier error. */
	@Test
	void testCofirmaExplicitaSHA512SobreFirmaExplicitaSHA512() throws Exception {

		final String algorithm = AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA;

		final byte[] result = this.signer.cosign(
				this.explicitSHA512Signature, algorithm,
				this.pke.getPrivateKey(), this.pke.getCertificateChain(), this.explicitParams);

		final File saveFile = saveTempFile(result);
		System.out.println("Prueba testCofirmaExplicitaSHA512SobreFirmaExplicitaSHA512: " + saveFile.getAbsolutePath()); //$NON-NLS-1$

		checkCosign(result, algorithm, false);
	}

	/** Esta firma no debe ser posible. Cofirma impl&iacute;cita con algoritmo SHA512withRSA sobre firma expl&iacute;cita
	 * con algoritmo de SHA256withRSA.
	 * @throws Exception en cualquier error. */
	@Test
	void testCofirmaImplicitaSHA512SobreFirmaExplicitaSHA256() throws Exception {
		Assertions.assertThrows(ContainsNoDataException.class, () -> {
			final String algorithm = AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA;
			this.signer.cosign(
					this.explicitSHA256Signature, algorithm,
					this.pke.getPrivateKey(), this.pke.getCertificateChain(), this.implicitParams);
			Assertions.fail("No debe ser posible cofirmar una firma sin los datos originales ni la huella en generada con el algoritmo usado en la firma"); //$NON-NLS-1$
		});
	}

	/** Cofirma impl&iacute;cita con algoritmo SHA512withRSA sobre firma impl&iacute;cita
	 * con algoritmo de SHA256withRSA.
	 * @throws Exception en cualquier error. */
	@Test
	void testCofirmaImplicitaSHA512SobreFirmaImplicitaSHA256() throws Exception {

		final String algorithm = AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA;

		final byte[] result = this.signer.cosign(
				this.implicitSHA256Signature, algorithm,
				this.pke.getPrivateKey(), this.pke.getCertificateChain(), this.implicitParams);

		final File saveFile = saveTempFile(result);
		System.out.println("Prueba testCofirmaImplicitaSHA512SobreFirmaImplicitaSHA256: " + saveFile.getAbsolutePath()); //$NON-NLS-1$

		checkCosign(result, algorithm, true);
	}

	/** Cofirma expl&iacute;cita con algoritmo SHA512withRSA sobre firma impl&iacute;cita
	 * con algoritmo de SHA256withRSA.
	 * @throws Exception en cualquier error. */
	@Test
	void testCofirmaExplicitaSHA512SobreFirmaImplicitaSHA256() throws Exception {

		final String algorithm = AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA;

		final byte[] result = this.signer.cosign(
				this.implicitSHA256Signature, algorithm,
				this.pke.getPrivateKey(), this.pke.getCertificateChain(), this.explicitParams);

		final File saveFile = saveTempFile(result);
		System.out.println("Prueba testCofirmaExplicitaSHA512SobreFirmaImplicitaSHA256: " + saveFile.getAbsolutePath()); //$NON-NLS-1$

		checkCosign(result, algorithm, true);
	}

	/** Cofirma impl&iacute;cita con algoritmo SHA512withRSA sobre firma impl&iacute;cita
	 * con algoritmo de SHA512withRSA indicando los datos a firmar.
	 * @throws Exception en cualquier error. */
	@Test
	void testCofirmaImplicitaSHA512ConDatosSobreFirmaImplicitaSHA512() throws Exception {

		final String algorithm = AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA;

		final byte[] result = this.signer.cosign(
				this.data, this.implicitSHA512Signature, algorithm,
				this.pke.getPrivateKey(), this.pke.getCertificateChain(), this.implicitParams);

		final File saveFile = saveTempFile(result);
		System.out.println("Prueba testCofirmaImplicitaSHA512ConDatosSobreFirmaImplicitaSHA512: " + saveFile.getAbsolutePath()); //$NON-NLS-1$

		checkCosign(result, algorithm, true);
	}

	/** Cofirma expl&iacute;cita con algoritmo SHA512withRSA sobre firma impl&iacute;cita
	 * con algoritmo de SHA512withRSA indicando los datos a firmar.
	 * @throws Exception en cualquier error. */
	@Test
	void testCofirmaExplicitaSHA512ConDatosSobreFirmaImplicitaSHA512() throws Exception {

		final String algorithm = AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA;

		final byte[] result = this.signer.cosign(
				this.data, this.implicitSHA512Signature, algorithm,
				this.pke.getPrivateKey(), this.pke.getCertificateChain(), this.explicitParams);

		final File saveFile = saveTempFile(result);
		System.out.println("Prueba testCofirmaExplicitaSHA512ConDatosSobreFirmaImplicitaSHA512: " + saveFile.getAbsolutePath()); //$NON-NLS-1$

		checkCosign(result, algorithm, true);
	}

	/** Cofirma impl&iacute;cita con algoritmo SHA512withRSA sobre firma expl&iacute;cita
	 * con algoritmo de SHA512withRSA indicando los datos a firmar.
	 * @throws Exception en cualquier error. */
	@Test
	void testCofirmaImplicitaSHA512ConDatosSobreFirmaExplicitaSHA512() throws Exception {

		final String algorithm = AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA;

		final byte[] result = this.signer.cosign(
				this.data, this.explicitSHA512Signature, algorithm,
				this.pke.getPrivateKey(), this.pke.getCertificateChain(), this.implicitParams);

		final File saveFile = saveTempFile(result);
		System.out.println("Prueba testCofirmaImplicitaSHA512ConDatosSobreFirmaExplicitaSHA512: " + saveFile.getAbsolutePath()); //$NON-NLS-1$

		checkCosign(result, algorithm, true);
	}

	/** Cofirma expl&iacute;cita con algoritmo SHA512withRSA sobre firma expl&iacute;cita
	 * con algoritmo de SHA512withRSA indicando los datos a firmar.
	 * @throws Exception en cualquier error. */
	@Test
	void testCofirmaExplicitaSHA512ConDatosSobreFirmaExplicitaSHA512() throws Exception {

		final String algorithm = AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA;

		final byte[] result = this.signer.cosign(
				this.data, this.explicitSHA512Signature, algorithm,
				this.pke.getPrivateKey(), this.pke.getCertificateChain(), this.explicitParams);

		final File saveFile = saveTempFile(result);
		System.out.println("Prueba testCofirmaExplicitaSHA512ConDatosSobreFirmaExplicitaSHA512: " + saveFile.getAbsolutePath()); //$NON-NLS-1$

		checkCosign(result, algorithm, false);
	}

	/** Esta firma no debe ser posible. Cofirma impl&iacute;cita con algoritmo SHA512withRSA sobre firma expl&iacute;cita
	 * con algoritmo de SHA256withRSA indicando los datos a firmar.
	 * @throws Exception en cualquier error. */
	@Test
	void testCofirmaImplicitaSHA512ConDatosSobreFirmaExplicitaSHA256() throws Exception {

		final String algorithm = AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA;

		final byte[] result = this.signer.cosign(
				this.data, this.explicitSHA256Signature, algorithm,
				this.pke.getPrivateKey(), this.pke.getCertificateChain(), this.implicitParams);

		final File saveFile = saveTempFile(result);
		System.out.println("Prueba testCofirmaImplicitaSHA512ConDatosSobreFirmaExplicitaSHA256: " + saveFile.getAbsolutePath()); //$NON-NLS-1$

		checkCosign(result, algorithm, true);
	}

	/** Cofirma impl&iacute;cita con algoritmo SHA512withRSA sobre firma impl&iacute;cita
	 * con algoritmo de SHA256withRSA indicando los datos a firmar.
	 * @throws Exception en cualquier error. */
	@Test
	void testCofirmaImplicitaSHA512ConDatosSobreFirmaImplicitaSHA256() throws Exception {

		final String algorithm = AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA;

		final byte[] result = this.signer.cosign(
				this.data, this.implicitSHA256Signature, algorithm,
				this.pke.getPrivateKey(), this.pke.getCertificateChain(), this.implicitParams);

		final File saveFile = saveTempFile(result);
		System.out.println("Prueba testCofirmaImplicitaSHA512ConDatosSobreFirmaImplicitaSHA256: " + saveFile.getAbsolutePath()); //$NON-NLS-1$

		checkCosign(result, algorithm, true);
	}

	/** Esta firma no debe ser posible. Cofirma expl&iacute;cita con algoritmo SHA512withRSA sobre firma expl&iacute;cita
	 * con algoritmo de SHA256withRSA indicando los datos a firmar.
	 * @throws Exception en cualquier error. */
	@Test
	void testCofirmaExplicitaSHA512ConDatosSobreFirmaExplicitaSHA256() throws Exception {

		final String algorithm = AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA;

		final byte[] result = this.signer.cosign(
				this.data, this.explicitSHA256Signature, algorithm,
				this.pke.getPrivateKey(), this.pke.getCertificateChain(), this.explicitParams);

		final File saveFile = saveTempFile(result);
		System.out.println("Prueba testCofirmaExplicitaSHA512ConDatosSobreFirmaExplicitaSHA256: " + saveFile.getAbsolutePath()); //$NON-NLS-1$

		checkCosign(result, algorithm, false);
	}

	/** Cofirma expl&iacute;cita con algoritmo SHA512withRSA sobre firma impl&iacute;cita
	 * con algoritmo de SHA256withRSA indicando los datos a firmar.
	 * @throws Exception en cualquier error. */
	@Test
	void testCofirmaExplicitaSHA512ConDatosSobreFirmaImplicitaSHA256() throws Exception {

		final String algorithm = AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA;

		final byte[] result = this.signer.cosign(
				this.data, this.implicitSHA256Signature, algorithm,
				this.pke.getPrivateKey(), this.pke.getCertificateChain(), this.explicitParams);

		final File saveFile = saveTempFile(result);
		System.out.println("Prueba testCofirmaExplicitaSHA512ConDatosSobreFirmaImplicitaSHA256: " + saveFile.getAbsolutePath()); //$NON-NLS-1$

		checkCosign(result, algorithm, true);
	}

	/**
	 * Guarda datos temporales en disco.
	 * @param data Datos a guardar.
	 * @return Fichero temporal generado.
	 * @throws IOException Cuando ocurre un error en el guardado del fichero en disco.
	 */
	private static File saveTempFile(final byte[] data) throws IOException {
		final File saveFile = File.createTempFile("testCoSign-", ".csig"); //$NON-NLS-1$ //$NON-NLS-2$
		try (OutputStream os = new FileOutputStream(saveFile)) {
			os.write(data);
		}
		return saveFile;
	}

	/**
	 * Realiza las comprobaciones necesarias sobre la firma generada.
	 * @param signature Firma generada.
	 * @param algorithm Algoritmo de firma empleado en la nueva firma.
	 * @param hasData Indica si la firma debe contener o no los datos originalmente firmados.
	 * @throws IOException Cuando ocurre un error al leer la firma.
	 * @throws AOException Cuando ocurre un error al extraer los datos originalmente firmados.
	 */
	private void checkCosign(final byte[] signature, final String algorithm, final boolean hasData) throws IOException, AOException {

		Assertions.assertNotNull(signature, "Se ha obtenido una cofirma nula"); //$NON-NLS-1$
		Assertions.assertTrue(this.signer.isSign(signature), "La cofirma no se reconoce como firma CAdES"); //$NON-NLS-1$

		final byte[] contentData = this.signer.getData(signature);
		if (hasData) {
			Assertions.assertNotNull(contentData, "No se han encontrado los datos en la cofirma"); //$NON-NLS-1$
			Assertions.assertNotEquals(contentData.length, 0, "El campo de datos de la firma esta vacio"); //$NON-NLS-1$
			Assertions.assertTrue(Arrays.equals(contentData, this.data), "Los datos extraidos de la firma no son los que originalmente se firmaron"); //$NON-NLS-1$
		}
		else {
			Assertions.assertNull(contentData, "El campo de datos de la firma deberia estar vacio"); //$NON-NLS-1$
		}

		final AOTreeModel tree = this.signer.getSignersStructure(signature, true);

		final AOTreeNode rootNode = (AOTreeNode) tree.getRoot();
		Assertions.assertEquals("Datos", rootNode.getUserObject(), "No se interpreto correctamente la estructura de la cofirma"); //$NON-NLS-1$ //$NON-NLS-2$

		AOSimpleSignInfo cosignInfo = null;

		for (int i = 0; i < rootNode.getChildCount(); i++) {
			final AOSimpleSignInfo signInfo = (AOSimpleSignInfo) rootNode.getChildAt(i).getUserObject();
			if (this.pke.getCertificate().equals(signInfo.getCerts()[0])) {
				cosignInfo = signInfo;
				break;
			}
		}

		Assertions.assertNotNull(cosignInfo, "No se encontro la cofirma generada en la nueva estructura de firma"); //$NON-NLS-1$
		Assertions.assertEquals(algorithm, cosignInfo.getSignAlgorithm(), "El algoritmo de firma no es el esperado"); //$NON-NLS-1$
		Assertions.assertNotNull(cosignInfo.getSigningTime(), "No se encontro la hora de firma"); //$NON-NLS-1$
	}
}
