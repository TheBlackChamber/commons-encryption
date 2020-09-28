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
 * The above copyright notice and this permission notice shall be included in
 * all
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

import static net.theblackchamber.crypto.constants.SupportedKeyGenAlgorithms.*;
import net.theblackchamber.crypto.constants.SupportedKeyGenAlgorithms;
import net.theblackchamber.crypto.exceptions.UnsupportedAlgorithmException;
import net.theblackchamber.crypto.exceptions.UnsupportedKeySizeException;
import net.theblackchamber.crypto.providers.symmetric.AESEncryptionProvider;
import net.theblackchamber.crypto.providers.symmetric.DESEdeEncryptionProvider;

/**
 * Factory which will create and return instances of {@link EncryptionProvider}
 * based on the algorithm of a key.
 * 
 * @author sminogue
 * 
 */
@Deprecated
public class EncryptionProviderFactory {

	/**
	 * Method which will return a new instance of {@link EncryptionProvider}
	 * based on the settings of the key passed in.
	 * 
	 * @param key
	 * @return 
	 * @return
	 * @throws UnsupportedAlgorithmException
	 * @throws UnsupportedKeySizeException
	 */
	public static EncryptionProvider getProvider(final Key key) throws UnsupportedAlgorithmException, UnsupportedKeySizeException {

		String algorithm = key.getAlgorithm();

		SupportedKeyGenAlgorithms keyAlgorithm = getAlgorithm(algorithm);

		switch (keyAlgorithm) {
		case AES:
			return new AESEncryptionProvider(key);
			
		case DES:
			return new DESEdeEncryptionProvider(key);
			
		default:
			throw new UnsupportedAlgorithmException("Algorithm [" + keyAlgorithm + "] is not supported.");
		}

	}

}
