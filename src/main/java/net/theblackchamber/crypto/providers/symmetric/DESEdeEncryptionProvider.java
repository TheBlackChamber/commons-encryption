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
package net.theblackchamber.crypto.providers.symmetric;

import java.security.Key;

import net.theblackchamber.crypto.constants.SupportedEncryptionAlgorithms;
import net.theblackchamber.crypto.exceptions.UnsupportedAlgorithmException;
import net.theblackchamber.crypto.exceptions.UnsupportedKeySizeException;
import net.theblackchamber.crypto.providers.EncryptionProvider;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.jasypt.encryption.pbe.PooledPBEByteEncryptor;
import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.SimplePBEConfig;
import org.jasypt.salt.RandomSaltGenerator;

/**
 * 
 * Implementation of {@link EncryptionProvider} which will implement the Triple
 * DES (DESede) algorithm.
 * 
 * Supported Key Sizes: 128 & 192
 * 
 * @author sminogue
 * @deprecated You should be using AESEncryptionProvider.
 */
@Deprecated
public class DESEdeEncryptionProvider extends EncryptionProvider {

	public DESEdeEncryptionProvider(Key key) throws UnsupportedKeySizeException, UnsupportedAlgorithmException {
		super(key);

		int keySize = (key.getEncoded().length) * 8;

		// Configure Encryptor
		SimplePBEConfig config = new SimplePBEConfig();

		switch (keySize) {

		default:
			config.setAlgorithm(SupportedEncryptionAlgorithms.DES.getAlgorithm());
			break;
		}

		config.setKeyObtentionIterations(10);
		config.setPassword(Hex.toHexString(key.getEncoded()));
		config.setProvider(new BouncyCastleProvider());
		config.setSaltGenerator(new RandomSaltGenerator());

		stringEncryptor = new PooledPBEStringEncryptor();
		stringEncryptor.setPoolSize(ENCRYPTOR_POOL_SIZE);
		stringEncryptor.setConfig(config);
		stringEncryptor.setStringOutputType("hexadecimal");

		byteEncryptor = new PooledPBEByteEncryptor();
		byteEncryptor.setPoolSize(ENCRYPTOR_POOL_SIZE);
		byteEncryptor.setConfig(config);

	}

	/**
	 * @see net.theblackchamber.crypto.providers.EncryptionProvider#validateKey(java.security.Key)
	 */
	@Override
	protected void validateKey(Key key) throws UnsupportedKeySizeException, UnsupportedAlgorithmException {
		byte[] keyBytes = key.getEncoded();
		// Validate Key Size for DES
		if (keyBytes.length != 16 && keyBytes.length != 24) {
			throw new UnsupportedKeySizeException(
					"Found unsupported key size ["
							+ (keyBytes.length * 8)
							+ "]. The DES algorithm only supports key sizes of 128, or 192");
		}

		if (!"DESede".equals(key.getAlgorithm())) {
			throw new UnsupportedAlgorithmException(
					"Key does not support DES algorithm: ["
							+ key.getAlgorithm() + "]");
		}
	}

}
