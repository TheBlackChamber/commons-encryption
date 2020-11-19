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
import net.theblackchamber.crypto.providers.digest.SHA256DigestProvider;
import net.theblackchamber.crypto.providers.digest.SHA256DigestProvider.TYPE;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.aead.AesGcmKeyManager;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.subtle.AesGcmJce;

/**
 * Utility used for managing a keystore. Generate keys etc.
 * 
 * @author sminogue
 * 
 */
public class KeystoreUtils2 {

	private static SHA256DigestProvider digest = new SHA256DigestProvider(TYPE.SHA1);
	
	/**
	 * Method which will generate a random Secret key and store it securely on disk.
	 * 
	 * @param config
	 *            Configuration for generation of key.
	 * @throws IOException
	 * @throws GeneralSecurityException 
	 */
	public static void generateSecretKey(KeyConfig2 config)
			throws IOException, GeneralSecurityException {

		if (config == null || config.getKeyStoreFile() == null || StringUtils.isBlank(config.getKeyPass())) {
			throw new KeyStoreException(
					"Missing parameters, unable to create keystore.");
		}
		TinkConfig.register();
		
		//Create rando key
		KeysetHandle keysetHandle = KeysetHandle.generateNew(
		        AesGcmKeyManager.aes256GcmTemplate());
				
		//using key-pass from config encrypt the encryption key
		String dKey = digest.digest(config.getKeyPass());
		AesGcmJce aesKey = new AesGcmJce(dKey.substring(0, 32).getBytes());
		ByteArrayOutputStream privateOutputStream = new ByteArrayOutputStream();
		keysetHandle.write(JsonKeysetWriter.withOutputStream(privateOutputStream), aesKey);
		
		//Store the key to disk.
		byte[] privateBytes = privateOutputStream.toByteArray();
		FileUtils.writeByteArrayToFile(config.getKeyStoreFile(), privateBytes);
        
	}

	/**
	 * Method which will load a secret key from disk with the specified entry
	 * name.
	 * 
	 * @param keystore
	 *            {@link KeyStore} file to read.
	 * @param keyStorePassword
	 *            Password used to open the {@link KeyStore}
	 * @return
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws GeneralSecurityException 
	 */
	public static KeysetHandle getSecretKey(KeyConfig2 config) throws IOException, GeneralSecurityException {
		

		if (config == null || config.getKeyStoreFile() == null || StringUtils.isBlank(config.getKeyPass())) {
			throw new KeyStoreException(
					"Missing parameters, unable to create keystore.");
		}
		
		TinkConfig.register();
		
		//Read and decrypt encrypted key from disk
		String dKey = digest.digest(config.getKeyPass());
		AesGcmJce aesKey = new AesGcmJce(dKey.substring(0, 32).getBytes());
		byte[] encryptedBytes = FileUtils.readFileToByteArray(config.getKeyStoreFile());
		return KeysetHandle.read(JsonKeysetReader.withBytes(encryptedBytes), aesKey);
		
	}

}
