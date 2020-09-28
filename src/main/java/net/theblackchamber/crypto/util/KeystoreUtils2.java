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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.theblackchamber.crypto.model.KeyConfig2;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.config.TinkConfig;

/**
 * Utility used for managing a keystore. Generate keys etc.
 * 
 * @author sminogue
 * 
 */
public class KeystoreUtils2 {


	/**
	 * Method which will generate a random Secret key and add it to a keystore
	 * with the entry name provided.
	 * 
	 * @param config
	 *            Configuration for generation of key.
	 * @throws IOException
	 * @throws GeneralSecurityException 
	 */
	public static void generateSecretKey(KeyConfig2 config)
			throws IOException, GeneralSecurityException {

		if (config == null || config.getKeyStoreFile() == null) {
			throw new KeyStoreException(
					"Missing parameters, unable to create keystore.");
		}
		TinkConfig.register();
		KeysetHandle keysetHandle = KeysetHandle.generateNew(
		        AeadKeyTemplates.AES256_GCM);
		
		CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withFile(config.getKeyStoreFile()));
		
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
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws GeneralSecurityException 
	 */
	public static KeysetHandle getSecretKey(File keystore) throws FileNotFoundException, IOException, GeneralSecurityException {
		
		if (keystore == null || !keystore.exists()
				|| FileUtils.sizeOf(keystore) == 0) {
			throw new FileNotFoundException();
		}
		
		TinkConfig.register();
		
		 return CleartextKeysetHandle.read(
			        JsonKeysetReader.withFile(keystore));

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
