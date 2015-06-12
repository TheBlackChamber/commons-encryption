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
package net.theblackchamber.crypto.providers;

import java.security.Key;

import javax.crypto.SecretKey;

import net.theblackchamber.crypto.exceptions.MissingParameterException;
import net.theblackchamber.crypto.exceptions.UnsupportedAlgorithmException;
import net.theblackchamber.crypto.exceptions.UnsupportedKeySizeException;

/**
 * Abstract class which will be the base for all Encryption providers. This is
 * kinda un-needed at the moment but I am adding it to support future plans to
 * allow more dynamic configuration of encryption used in utilities.
 * 
 * @author sminogue
 * 
 */
public abstract class EncryptionProvider<T extends Key> {

	/**
	 * Encryption {@link Key} to be used for encryption and decryption options.
	 */
	private T key;

	/**
	 * Method which will return the {@link Key} being used by the instance of
	 * this provider.
	 * 
	 * @return
	 */
	protected T getKey() {
		return key;
	}

	/**
	 * Method which will set the {@link Key} to be used by the instance of this
	 * provider.
	 * 
	 * @param key
	 *            Instance of {@link Key} to be used for encryption and
	 *            decryption.
	 */
	protected void setKey(final T key) {
		this.key = key;
	}

	/**
	 * Method which will decrypt a string.
	 * 
	 * @param cipherText
	 *            Encrypted text to be decrypted.
	 * @return
	 * @throws MissingParameterException 
	 */
	public abstract String decrypt(String cipherText) throws MissingParameterException;

	/**
	 * Method which will encrypt a string.
	 * 
	 * @param clearText
	 *            Clear text to be encrypted.
	 * @return Encrypted text.
	 * @throws MissingParameterException 
	 */
	public abstract String encrypt(String clearText) throws MissingParameterException;

	/**
	 * Method which will validate that the key passed to the provider is
	 * appropriate. Meaning it is correct length of the algorithm, that its for
	 * the correct algorithm, etc.
	 * 
	 * @param key
	 * @throws UnsupportedKeySizeException 
	 * @throws UnsupportedAlgorithmException 
	 */
	protected abstract void validateKey(T key) throws UnsupportedKeySizeException, UnsupportedAlgorithmException;

	/**
	 * Constructor used by all implementations of {@link EncryptionProvider}
	 * which will provide common setup operations.
	 * 
	 * @param key
	 *            Instance of {@link SecretKey} to be used for encryption and
	 *            decryption.
	 * @throws UnsupportedKeySizeException
	 * @throws UnsupportedAlgorithmException 
	 */
	public EncryptionProvider(T key) throws UnsupportedKeySizeException, UnsupportedAlgorithmException {
		validateKey(key);
		setKey(key);
	}

}
