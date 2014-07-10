/**
 * 
 */
package net.theblackchamber.crypto.providers;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.InvalidPropertiesFormatException;
import java.util.Properties;

import javax.crypto.SecretKey;

import org.apache.commons.lang3.StringUtils;

import net.theblackchamber.crypto.util.KeystoreUtils;

public class SecurePropertiesProvider extends Properties {

	private static final long serialVersionUID = 6795084558089471182L;

	private SecretKey key = null;

	private AESEncryptionProvider encryptionProvider;

	
	
	public SecretKey getKey() {
		return key;
	}

	public AESEncryptionProvider getEncryptionProvider() {
		return encryptionProvider;
	}

	/**
	 * Default constructor.
	 */
	public SecurePropertiesProvider() {
		super();
	}

	/**
	 * Constructor which specifies {@link Properties} defaults.
	 * 
	 * @throws IOException
	 * @throws UnrecoverableEntryException
	 * @throws FileNotFoundException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 */
	public SecurePropertiesProvider(Properties defaults)
			throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, FileNotFoundException,
			UnrecoverableEntryException, IOException {
		super(defaults);
		loadKeystore();
		initializeEncryptionProvider();
	}

	/**
	 * @see java.util.Properties#load(java.io.Reader) Also loads encryption
	 *      keystore if it exists.
	 * @throws RuntimeException
	 *             Wraps encryption key loading errors.
	 */
	@Override
	public synchronized void load(Reader reader) throws IOException {
		super.load(reader);
		loadKeystore();
		initializeEncryptionProvider();
	}

	/**
	 * @see java.util.Properties#load(java.io.InputStream) Also loads encryption
	 *      keystore if it exists.
	 * @throws RuntimeException
	 *             Wraps encryption key loading errors.
	 */
	@Override
	public synchronized void load(InputStream inStream) throws IOException {
		super.load(inStream);
		loadKeystore();
		initializeEncryptionProvider();
	}

	/**
	 * @see java.util.Properties#loadFromXML(java.io.InputStream) Also loads
	 *      encryption keystore if it exists.
	 * @throws RuntimeException
	 *             Wraps encryption key loading errors.
	 */
	@Override
	public synchronized void loadFromXML(InputStream in) throws IOException,
			InvalidPropertiesFormatException {
		super.loadFromXML(in);
		loadKeystore();
		initializeEncryptionProvider();
	}

	/**
	 * @see java.util.Properties#getProperty(java.lang.String) If property key
	 *      ends in "-encrypted" this method will attempt to decrypt before
	 *      returning the value.
	 * @throws RuntimeException
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
	 * @throws RuntimeException
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
	 *      specified key.
	 * @throws RuntimeException
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
		if(!StringUtils.equals(property, value)){
			key = StringUtils.replace(key, "-unencrypted", "-encrypted");
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
	 * @return
	 */
	private String attemptDecryption(String key, String property) {

		if (StringUtils.endsWithIgnoreCase(key, "-encrypted")) {
			if (encryptionProvider == null)
				throw new RuntimeException("No encryption provider configured");
			return encryptionProvider.decrypt(property);
		} else {
			return property;
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
	 * @return
	 */
	private String attemptEncryption(String key, String property) {

		if (StringUtils.endsWithIgnoreCase(key, "-unencrypted")) {
			if (encryptionProvider == null)
				throw new RuntimeException("No encryption provider configured");
			return encryptionProvider.encrypt(property);
		} else {
			return property;
		}

	}

	private void initializeEncryptionProvider() {
		if (key != null) {
			encryptionProvider = new AESEncryptionProvider(key);
		}
	}

	/**
	 * Method will get the key-path from this properties object and attempt to
	 * load the keystore from file.
	 * 
	 * @throws RuntimeException
	 *             Wraps encryption key loading errors.
	 */
	private void loadKeystore() {
		String keypath = this.getProperty("key-path");

		if (keypath != null) {
			try {
				key = KeystoreUtils.getAESSecretKey(new File(keypath));
			} catch (Throwable t) {
				throw new RuntimeException(
						"Failed when attempting to load keystore: "
								+ t.getMessage(), t);
			}
		}
	}

}
