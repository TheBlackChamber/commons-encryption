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

import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.SecretKey;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.config.TinkConfig;

import static net.theblackchamber.crypto.constants.SupportedKeyGenAlgorithms.*;
import net.theblackchamber.crypto.constants.SupportedKeyGenAlgorithms;
import net.theblackchamber.crypto.exceptions.UnsupportedAlgorithmException;
import net.theblackchamber.crypto.exceptions.UnsupportedKeySizeException;
import net.theblackchamber.crypto.providers.symmetric.AESEncryptionProvider;
import net.theblackchamber.crypto.providers.symmetric.AESEncryptionProvider2;
import net.theblackchamber.crypto.providers.symmetric.DESEdeEncryptionProvider;

/**
 * Factory which will create and return instances of {@link EncryptionProvider}
 * based on the algorithm of a key.
 * 
 * @author sminogue
 * 
 */
public class EncryptionProviderFactory2 {

	/**
	 * Method which will return a new instance of {@link EncryptionProvider}
	 * @throws GeneralSecurityException 
	 * 
	 */
	public static EncryptionProvider2 getProvider(KeysetHandle key) throws  GeneralSecurityException {

		TinkConfig.register();

		return new AESEncryptionProvider2(key);

	}

}
