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
package net.theblackchamber.crypto.implementations;

import static net.theblackchamber.crypto.constants.Constants.ENTRY_NAME_PROPERTY_KEY;
import static net.theblackchamber.crypto.constants.Constants.KEYSTORE_PASSWORD_PROPERTY_KEY;
import static net.theblackchamber.crypto.constants.Constants.KEY_PATH_PROPERTY_KEY;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.InvalidPropertiesFormatException;
import java.util.Properties;

import net.theblackchamber.crypto.constants.Constants;
import net.theblackchamber.crypto.exceptions.MissingParameterException;
import net.theblackchamber.crypto.exceptions.RuntimeCryptoException;
import net.theblackchamber.crypto.exceptions.UnsupportedAlgorithmException;
import net.theblackchamber.crypto.exceptions.UnsupportedKeySizeException;
import net.theblackchamber.crypto.providers.EncryptionProvider;
import net.theblackchamber.crypto.providers.EncryptionProvider2;
import net.theblackchamber.crypto.providers.EncryptionProviderFactory;
import net.theblackchamber.crypto.providers.EncryptionProviderFactory2;
import net.theblackchamber.crypto.util.KeystoreUtils;
import net.theblackchamber.crypto.util.KeystoreUtils2;

import org.apache.commons.lang3.StringUtils;

import com.google.crypto.tink.KeysetHandle;

/**
 * Extension of the java {@link Properties} class which will provide the ability
 * to transparently use encrypted properties.<br>
 * Usage: In order to make use of encryped properties the properties file should
 * contain an entry key-path which will point to a keystore file created via
 * {@link KeystoreUtils}.<br>
 * Calling setProperty on a new property with name containing "-unencrypted"
 * will result in the value being added to the {@link Properties} map with the
 * name changed from XX-unencrypted to XX-encrypted and the value being encoded.<br>
 * Calling getProperty for a property with key containing -encrypted in the name
 * will result in the value being decoded and the clear text value returned.
 * 
 * @author sminogue
 * 
 */
public class SecureProperties2 extends Properties {

	private static final long serialVersionUID = 6795084558089471182L;
	private static final String ENCRYPTED_SUFFIX = "-encrypted";
	private static final String UNENCRYPTED_SUFFIX = "-unencrypted";
	private KeysetHandle key = null;
	private EncryptionProvider2 encryptionProvider = null;

	/**
	 * Gets the encryption key to be used for encryption and decryption. The
	 * path to <b>this file will have been specified in the properties file with
	 * the key: "key-path" or have been passed in by parameter</b>
	 * 
	 * @return
	 */
	public KeysetHandle getKey() {
		return key;
	}

	/**
	 * Gets the encryption provider. This is the Provider which will be used to
	 * encrypt and decrypt properties.
	 * 
	 * @return
	 */
	public EncryptionProvider2 getEncryptionProvider() {
		return encryptionProvider;
	}

	/**
	 * Default constructor.
	 */
	public SecureProperties2() {
		super();
	}

	/**
	 * Constructor which specifies file path to load properties from and the
	 * keystore details. <b>Note that if an exception occurred in
	 * encryption/decryption methods the IOException will wrap the underlying
	 * exception</b>
	 * 
	 * @param propertiesPath
	 * @param keyPath
	 * @param keyEntry
	 * @param keyPass
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws FileNotFoundException
	 * @throws UnrecoverableEntryException
	 * @throws IOException
	 */
	public SecureProperties2(String propertiesPath, String keyPath) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException,
			FileNotFoundException, UnrecoverableEntryException, IOException {
		super();
		super.load(new FileInputStream(new File(propertiesPath)));
		try {
			loadKeystore(keyPath);
			initializeEncryptionProvider();
		} catch (RuntimeCryptoException rce) {
			throw new IOException(rce);
		}
	}

	/**
	 * Constructor which specifies an inputstream to load properties from and
	 * the keystore details. <b>Note that if an exception occurred in
	 * encryption/decryption methods the IOException will wrap the underlying
	 * exception</b>
	 * 
	 * @param inputStream
	 * @param keyPath
	 *            If null an attempt will be made to attempt to use the key path
	 *            property from the underlying property file.
	 * @param keyEntry
	 *            If null an attempt will be made to attempt to use the key
	 *            entry property from the underlying property file.
	 * @param keyPass
	 *            If null an attempt will be made to attempt to use the key pass
	 *            property from the underlying property file.
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws FileNotFoundException
	 * @throws UnrecoverableEntryException
	 * @throws IOException
	 */
	public SecureProperties2(InputStream inputStream, String keyPath) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException,
			FileNotFoundException, UnrecoverableEntryException, IOException {
		super();
		super.load(inputStream);
		try {
			// If KeyPass/KeyEntry/keyPath arent passed in, check if they are in
			// the properties.
			if (StringUtils.isEmpty(keyPath)) {
				keyPath = this.getProperty(Constants.KEY_PATH_PROPERTY_KEY);
			}
			loadKeystore(keyPath);
			initializeEncryptionProvider();
		} catch (RuntimeCryptoException rce) {
			throw new IOException(rce);
		}
	}

	/**
	 * Constructor which specifies file to load properties from and the keystore
	 * details. <b>Note that if an exception occurred in encryption/decryption
	 * methods the IOException will wrap the underlying exception</b>
	 * 
	 * @param propertiesFile
	 * @param keyPath
	 *            If null an attempt will be made to attempt to use the key path
	 *            property from the underlying property file.
	 * @param keyEntry
	 *            If null an attempt will be made to attempt to use the key
	 *            entry property from the underlying property file.
	 * @param keyPass
	 *            If null an attempt will be made to attempt to use the key pass
	 *            property from the underlying property file.
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws FileNotFoundException
	 * @throws UnrecoverableEntryException
	 * @throws IOException
	 */
	public SecureProperties2(File propertiesFile, String keyPath) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException,
			FileNotFoundException, UnrecoverableEntryException, IOException {
		super();
		super.load(new FileInputStream(propertiesFile));
		try {
			if (StringUtils.isEmpty(keyPath)) {
				keyPath = this.getProperty(Constants.KEY_PATH_PROPERTY_KEY);
			}
			loadKeystore(keyPath);
			initializeEncryptionProvider();
		} catch (RuntimeCryptoException rce) {
			throw new IOException(rce);
		}
	}

	/**
	 * Constructor which specifies {@link Properties} defaults and the keystore
	 * details. <b>Note that if an exception occurred in encryption/decryption
	 * methods the IOException will wrap the underlying exception</b>
	 * 
	 * @param defaults
	 * @param keyPath
	 *            If null an attempt will be made to attempt to use the key path
	 *            property from the underlying property file.
	 * @param keyEntry
	 *            If null an attempt will be made to attempt to use the key
	 *            entry property from the underlying property file.
	 * @param keyPass
	 *            If null an attempt will be made to attempt to use the key pass
	 *            property from the underlying property file.
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws FileNotFoundException
	 * @throws UnrecoverableEntryException
	 * @throws IOException
	 */
	public SecureProperties2(Properties defaults, String keyPath) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException,
			FileNotFoundException, UnrecoverableEntryException, IOException {
		super(defaults);
		try {
			if (StringUtils.isEmpty(keyPath)) {
				keyPath = this.getProperty(Constants.KEY_PATH_PROPERTY_KEY);
			}
			loadKeystore(keyPath);
			initializeEncryptionProvider();
		} catch (RuntimeCryptoException rce) {
			throw new IOException(rce);
		}
	}

	/**
	 * Constructor which specifies file path to load properties from. <b>Note
	 * that if an exception occurred in encryption/decryption methods the
	 * IOException will wrap the underlying exception</b>
	 * 
	 * @param propertiesPath
	 * @throws IOException
	 * @throws UnrecoverableEntryException
	 * @throws FileNotFoundException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 */
	public SecureProperties2(String propertiesPath) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException,
			FileNotFoundException, UnrecoverableEntryException, IOException {
		super();
		super.load(new FileInputStream(new File(propertiesPath)));
		try {
			loadKeystore();
			initializeEncryptionProvider();
		} catch (RuntimeCryptoException rce) {
			throw new IOException(rce);
		}
	}

	/**
	 * Constructor which specifies file path to load properties from. <b>Note
	 * that if an exception occurred in encryption/decryption methods the
	 * IOException will wrap the underlying exception</b>
	 * 
	 * @param propertiesFile
	 * @throws IOException
	 * @throws UnrecoverableEntryException
	 * @throws FileNotFoundException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 */
	public SecureProperties2(File propertiesFile) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException,
			FileNotFoundException, UnrecoverableEntryException, IOException {
		super();
		super.load(new FileInputStream(propertiesFile));
		try {
			loadKeystore();
			initializeEncryptionProvider();
		} catch (RuntimeCryptoException rce) {
			throw new IOException(rce);
		}
	}

	/**
	 * Constructor which specifies {@link Properties} defaults. <b>Note that if
	 * an exception occurred in encryption/decryption methods the IOException
	 * will wrap the underlying exception</b>
	 * 
	 * @param defaults
	 * @throws IOException
	 * @throws UnrecoverableEntryException
	 * @throws FileNotFoundException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 */
	public SecureProperties2(Properties defaults) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException,
			FileNotFoundException, UnrecoverableEntryException, IOException {
		super(defaults);
		try {
			loadKeystore();
			initializeEncryptionProvider();
		} catch (RuntimeCryptoException rce) {
			throw new IOException(rce);
		}
	}

	/**
	 * Constructor which specifies an inputStream to read from. <b>Note that if
	 * an exception occurred in encryption/decryption methods the IOException
	 * will wrap the underlying exception</b>
	 * 
	 * @param inputStream
	 * @throws IOException
	 * @throws UnrecoverableEntryException
	 * @throws FileNotFoundException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 */
	public SecureProperties2(InputStream inputStream) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException,
			FileNotFoundException, UnrecoverableEntryException, IOException {
		super();
		super.load(inputStream);
		try {
			loadKeystore();
			initializeEncryptionProvider();
		} catch (RuntimeCryptoException rce) {
			throw new IOException(rce);
		}
	}

	/**
	 * @see java.util.Properties#load(java.io.Reader) Also loads encryption
	 *      keystore if it exists. <b>Note that if an exception occurred in
	 *      encryption/decryption methods the IOException will wrap the
	 *      underlying exception</b>
	 */
	@Override
	public synchronized void load(Reader reader) throws IOException {
		super.load(reader);
		try {
			loadKeystore();
			initializeEncryptionProvider();
		} catch (RuntimeCryptoException rce) {
			throw new IOException(rce);
		}
	}

	/**
	 * @see java.util.Properties#load(java.io.InputStream) Also loads encryption
	 *      keystore if it exists. <b>Note that if an exception occurred in
	 *      encryption/decryption methods the IOException will wrap the
	 *      underlying exception</b>
	 */
	@Override
	public synchronized void load(InputStream inStream) throws IOException {
		super.load(inStream);
		try {
			loadKeystore();
			initializeEncryptionProvider();
		} catch (RuntimeCryptoException rce) {
			throw new IOException(rce);
		}
	}

	/**
	 * @see java.util.Properties#loadFromXML(java.io.InputStream) Also loads
	 *      encryption keystore if it exists. <b>Note that if an exception
	 *      occurred in encryption/decryption methods the IOException will wrap
	 *      the underlying exception</b>
	 */
	@Override
	public synchronized void loadFromXML(InputStream in) throws IOException,
			InvalidPropertiesFormatException {
		super.loadFromXML(in);
		try {
			loadKeystore();
			initializeEncryptionProvider();
		} catch (RuntimeCryptoException rce) {
			throw new IOException(rce);
		}
	}

	/**
	 * @see java.util.Properties#getProperty(java.lang.String) If property key
	 *      ends in "-encrypted" this method will attempt to decrypt before
	 *      returning the value.
	 * @throws RuntimeCryptoException
	 *             If no encryption key was configured. This usually happens
	 *             when no key was successfully loaded. .
	 */
	@Override
	public String getProperty(String key) {
		String property = super.getProperty(key);
		return attemptDecryption(key, property);
	}

	/**
	 * @see java.util.Properties#getProperty(java.lang.String, java.lang.String)
	 *      If property key ends in "-encrypted" this method will attempt to
	 *      decrypt before returning the value.
	 * @throws RuntimeCryptoException
	 *             If no encryption key was configured. This usually happens
	 *             when no key was successfully loaded.
	 */
	@Override
	public String getProperty(String key, String defaultValue) {
		String property = getProperty(key);
		if (StringUtils.isEmpty(property)) {
			return defaultValue;
		} else {
			return property;
		}
	}

	/**
	 * @see java.util.Properties#setProperty(java.lang.String, java.lang.String)
	 *      If property key ends in -unencrypted this method will attempt to
	 *      encrypt the value prior to adding it. If the property key is
	 *      "key-path" then the encryption will be re-initialized using the
	 *      specified key. NOTE: If you specify key-path its important to have
	 *      FIRST specified entry-name and keystore-password or an error will
	 *      occur.
	 * @throws RuntimeCryptoException
	 *             If no encryption key was configured. This usually happens
	 *             when no key was successfully loaded.
	 */
	@Override
	public synchronized Object setProperty(String key, String value) {

		if (StringUtils.equalsIgnoreCase("key-path", key)) {
			super.setProperty(key, value);
			loadKeystore();
			initializeEncryptionProvider();
		}

		String property = attemptEncryption(key, value);
		if (!StringUtils.equals(property, value)) {
			key = StringUtils
					.replace(key, UNENCRYPTED_SUFFIX, ENCRYPTED_SUFFIX);
		}
		return super.setProperty(key, property);
	}

	/**
	 * Utility method which will determine if a requested property needs to be
	 * decrypted. If property key ends in -encrypted and the encryption provider
	 * is configured this method will return the decrypted property value. If
	 * the key does not include -encrypted then the property value will be
	 * returned.
	 * 
	 * @param key
	 * @param property
	 * @throws RuntimeCryptoException
	 *             If no encryption provider is configured.
	 * @return
	 */
	private String attemptDecryption(String key, String property) {
		try {
			if (StringUtils.endsWithIgnoreCase(key, ENCRYPTED_SUFFIX)) {
				if (encryptionProvider == null)
					throw new RuntimeCryptoException(
							"No encryption provider configured");

				return encryptionProvider.decrypt(property);

			} else {
				return property;
			}
		} catch (MissingParameterException e) {
			throw new RuntimeCryptoException("No value to encrypt specified");
		} catch (GeneralSecurityException e) {
			throw new RuntimeCryptoException(
					"Error Decrypting: " + e.getMessage(),e);
		}
	}

	/**
	 * Utility method which will determine if a requested property needs to be
	 * encrypted. If property key ends in -unencrypted and the encryption
	 * provider is configured this method will return the encrypted property
	 * value. If the key does not include -unencrypted then the property value
	 * will be returned.
	 * 
	 * @param key
	 * @param property
	 * @throws RuntimeCryptoException
	 *             If not encryption provider is configured.
	 * @return
	 */
	private String attemptEncryption(String key, String property) {
		try {
			if (StringUtils.endsWithIgnoreCase(key, UNENCRYPTED_SUFFIX)) {
				if (encryptionProvider == null)
					throw new RuntimeCryptoException(
							"No encryption provider configured");
				return encryptionProvider.encrypt(property);
			} else {
				return property;
			}
		} catch (MissingParameterException mpre) {
			throw new RuntimeCryptoException("No value to decrypt specified.");
		} catch (GeneralSecurityException e) {
			throw new RuntimeCryptoException("Error encrypting: " + e.getMessage(),e);
		}
	}

	/**
	 * Method which will create a new Encryption provider using the already
	 * specified key.
	 */
	private void initializeEncryptionProvider() {
		if (key != null) {
			try {
				encryptionProvider = EncryptionProviderFactory2.getProvider(key);
			} catch (GeneralSecurityException e) {
				throw new RuntimeCryptoException(e.getMessage(), e);
			} 
		}
	}

	/**
	 * Method will load the KeyStore from file using the key path, entry name,
	 * and keystore password from the properties file.
	 * 
	 * @throws RuntimeCryptoException
	 *             Wraps encryption key loading errors.
	 */
	private void loadKeystore() {
		String keypath = this.getProperty(KEY_PATH_PROPERTY_KEY);

		loadKeystore(keypath);

	}

	/**
	 * 
	 * Method will load the KeyStore from file using the Key Path, Key Entry,
	 * and Key Password specified.
	 * 
	 * @param keyPath
	 *            Path to keystore file.
	 * @param keyPass
	 *            Password to open keystore.
	 * @param keyEntry
	 *            Entry name for the key in the keystore.
	 * 
	 * @throws RuntimeCryptoException
	 *             Wraps encryption key loading errors.
	 * 
	 */
	private void loadKeystore(String keyPath) {
		if (!StringUtils.isEmpty(keyPath)) {
			try {
				key = KeystoreUtils2.getSecretKey(new File(keyPath));
			} catch (Throwable t) {
				throw new RuntimeCryptoException(
						"Failed when attempting to load keystore: "
								+ t.getMessage(), t);
			}
		}
	}

}
