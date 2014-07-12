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
package net.theblackchamber.crypto.model;

import java.io.File;

import net.theblackchamber.crypto.constants.SupportedAlgorithms;

/**
 * Class used to configure key generation. 
 * @author sminogue
 *
 */
public class KeyConfig {

	private static final int DEFAULT_KEY_SIZE = 256;

	private File keyStoreFile = null;
	private String keyStorePassword = null;
	private Integer keySize = null;
	private SupportedAlgorithms algorithm = null;
	private String keyEntryName = null;

	/**
	 * Constructor
	 */
	public KeyConfig() {
		super();
	}

	/**
	 * Constructor
	 * 
	 * @param keyStoreFile Key Store file to add a key to.
	 * @param keyStorePassword Password to be used to secure the keystore or open the keystore if it aleady exists.
	 * @param keySize Size in bits of the key to generate.
	 * @param algorithm Algorithm the key is for
	 * @param keyEntryName Entry name for the key in the keystore.
	 */
	public KeyConfig(final File keyStoreFile, final String keyStorePassword,
			final Integer keySize, final SupportedAlgorithms algorithm,
			final String keyEntryName) {
		super();
		this.keyStoreFile = keyStoreFile;
		this.keyStorePassword = keyStorePassword;
		this.keySize = keySize;
		this.algorithm = algorithm;
		this.keyEntryName = keyEntryName;
	}

	/**
	 * Gets the KeyStore file to be used.
	 * 
	 * @return
	 */
	public File getKeyStoreFile() {
		return keyStoreFile;
	}

	/**
	 * Sets the KeyStore file to be used.
	 * 
	 * @param keyStoreFile
	 */
	public void setKeyStoreFile(final File keyStoreFile) {
		this.keyStoreFile = keyStoreFile;
	}

	/**
	 * Gets the keystore password. 
	 * 
	 * @return
	 */
	public String getKeyStorePassword() {
		return keyStorePassword;
	}

	/**
	 * Get the name of the key entry in the keystore.
	 * 
	 * @return
	 */
	public String getKeyEntryName() {
		return keyEntryName;
	}

	/**
	 * Sets the name of the key entry in the keystore.
	 * 
	 * @param keyEntryName
	 */
	public void setKeyEntryName(final String keyEntryName) {
		this.keyEntryName = keyEntryName;
	}

	/**
	 * Sets the password to be used to secure the keystore. See
	 * getKeyStorePassword for more information concerning if this is not
	 * specified.
	 * 
	 * @param keyStorePassword
	 */
	public void setKeyStorePassword(final String keyStorePassword) {
		this.keyStorePassword = keyStorePassword;
	}

	/**
	 * Get the keysize. If no key size specified this will return the default
	 * key size.
	 * 
	 * @return
	 */
	public Integer getKeySize() {
		return keySize == null ? DEFAULT_KEY_SIZE : keySize;
	}

	/**
	 * Sets the keysize. See getKeySize for more information concerning if this
	 * is not specified.
	 * 
	 * @param keySize
	 */
	public void setKeySize(final Integer keySize) {
		this.keySize = keySize;
	}

	/**
	 * Gets the algorithm to generate a key for.
	 * 
	 * @return
	 */
	public SupportedAlgorithms getAlgorithm() {
		return algorithm;
	}

	/**
	 * Sets the algorithm to generate a key for.
	 * 
	 * @param algorithm
	 */
	public void setAlgorithm(final SupportedAlgorithms algorithm) {
		this.algorithm = algorithm;
	}

}
