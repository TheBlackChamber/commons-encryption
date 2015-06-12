/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Seamus Minogue
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package net.theblackchamber.crypto.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import net.theblackchamber.crypto.model.KeyConfig;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Utility used for managing a keystore. Generate keys etc.
 * 
 * @author sminogue
 * 
 */
public class KeystoreUtils {


	/**
	 * Method which will generate a random Secret key and add it to a keystore
	 * with the entry name provided.
	 * 
	 * @param config
	 *            Configuration for generation of key.
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws IOException
	 */
	public static void generateSecretKey(KeyConfig config)
			throws NoSuchAlgorithmException, KeyStoreException,
			CertificateException, IOException {

		if (config == null || config.getKeyStoreFile() == null
				|| StringUtils.isEmpty(config.getKeyEntryName())
				|| config.getAlgorithm() == null) {
			throw new KeyStoreException(
					"Missing parameters, unable to create keystore.");
		}

		SecureRandom random = new SecureRandom();

		KeyGenerator keygen = KeyGenerator.getInstance(config.getAlgorithm()
				.getName(), new BouncyCastleProvider());
		keygen.init(config.getKeySize(), random);

		SecretKey key = keygen.generateKey();

		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		FileInputStream fis = null;
		if (config.getKeyStoreFile().exists()
				&& FileUtils.sizeOf(config.getKeyStoreFile()) > 0) {
			fis = new FileInputStream(config.getKeyStoreFile());
		}

		keyStore.load(fis, config.getKeyStorePassword().toCharArray());

		KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(
				config.getKeyStorePassword().toCharArray());
		KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(
				key);

		keyStore.setEntry(config.getKeyEntryName(), secretKeyEntry,
				protectionParameter);
		if (fis != null) {
			fis.close();
		}
		FileOutputStream fos = new FileOutputStream(config.getKeyStoreFile());

		keyStore.store(fos, config.getKeyStorePassword().toCharArray());

		fos.close();

	}

	/**
	 * Method which will load a secret key from disk with the specified entry
	 * name.
	 * 
	 * @param keystore
	 *            {@link KeyStore} file to read.
	 * @param entryName
	 *            Entry name of the key to be retrieved
	 * @param keyStorePassword
	 *            Password used to open the {@link KeyStore}
	 * @return
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws UnrecoverableEntryException
	 */
	public static SecretKey getSecretKey(File keystore, String entryName,
			String keyStorePassword) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException,
			FileNotFoundException, IOException, UnrecoverableEntryException {
		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		FileInputStream fis = null;
		if (keystore == null || !keystore.exists()
				|| FileUtils.sizeOf(keystore) == 0) {
			throw new FileNotFoundException();
		}
		if (StringUtils.isEmpty(keyStorePassword)) {
			throw new KeyStoreException("No Keystore password provided.");
		}
		if (StringUtils.isEmpty(entryName)) {
			throw new KeyStoreException("No Keystore entry name provided.");
		}

		fis = new FileInputStream(keystore);

		return getSecretKey(fis, entryName, keyStorePassword);

	}

	/**
	 * Method which will load a secret key from an input stream with the
	 * specified entry name.
	 * 
	 * @param keystore
	 *            {@link KeyStore} file to read.
	 * @param entryName
	 *            Entry name of the key to be retrieved
	 * @param keyStorePassword
	 *            Password used to open the {@link KeyStore}
	 * @return
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws UnrecoverableEntryException
	 */
	public static SecretKey getSecretKey(InputStream keyInputStream,
			String entryName, String keyStorePassword)
			throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException, UnrecoverableEntryException {
		KeyStore keyStore = KeyStore.getInstance("JCEKS");

		if (keyInputStream == null) {
			throw new KeyStoreException("No Keystore stream provided.");
		}
		if (StringUtils.isEmpty(keyStorePassword)) {
			throw new KeyStoreException("No Keystore password provided.");
		}
		if (StringUtils.isEmpty(entryName)) {
			throw new KeyStoreException("No Keystore entry name provided.");
		}

		keyStore.load(keyInputStream, keyStorePassword.toCharArray());
		KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(
				keyStorePassword.toCharArray());
		KeyStore.SecretKeyEntry pkEntry = (KeyStore.SecretKeyEntry) keyStore
				.getEntry(entryName, protectionParameter);
		try {
			return pkEntry.getSecretKey();
		} finally {
			keyInputStream.close();
		}

	}

}
