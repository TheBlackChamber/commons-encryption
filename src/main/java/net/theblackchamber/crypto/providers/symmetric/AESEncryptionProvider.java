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

import javax.crypto.SecretKey;

import net.theblackchamber.crypto.constants.SupportedEncryptionAlgorithms;
import net.theblackchamber.crypto.exceptions.MissingParameterException;
import net.theblackchamber.crypto.exceptions.UnsupportedAlgorithmException;
import net.theblackchamber.crypto.exceptions.UnsupportedKeySizeException;
import net.theblackchamber.crypto.providers.EncryptionProvider;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.jasypt.encryption.pbe.PooledPBEByteEncryptor;
import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.SimplePBEConfig;
import org.jasypt.salt.RandomSaltGenerator;

/**
 * Provider which will allow for encryption and decryption of strings using the
 * AES algorithm. <br>
 * Usage: <code>
 * SecretKey key = KeystoreUtils.getAESSecretKey(keyfile, "aes-key", "TEST");
 * AESEncryptionProvider encryptionProvider = new AESEncryptionProvider(key);
 * String cipherText = encryptionProvider.encode("clear text");
 * </code>
 * 
 * Supported Key Sizes: 128, 192, & 256
 * 
 * @author sminogue
 * @deprecated Use AESEncryptionProvider2
 */
@Deprecated
public class AESEncryptionProvider extends EncryptionProvider {

	/**
	 * Constructor to create new AES encryption provider.
	 * 
	 * @param key
	 *            Instance of {@link SecretKey} to be used for encryption and
	 *            decryption.
	 * @throws UnsupportedKeySizeException
	 * @throws UnsupportedAlgorithmException
	 */
	public AESEncryptionProvider(final Key key)
			throws UnsupportedKeySizeException, UnsupportedAlgorithmException {
		super(key);

		int keySize = (key.getEncoded().length) * 8;

		// Configure Encryptor
		SimplePBEConfig config = new SimplePBEConfig();

		switch (keySize) {
		case 128:
			config.setAlgorithm(SupportedEncryptionAlgorithms.AES128.getAlgorithm());
			break;

		case 192:
			config.setAlgorithm(SupportedEncryptionAlgorithms.AES192.getAlgorithm());
			break;

		default:
			config.setAlgorithm(SupportedEncryptionAlgorithms.AES256.getAlgorithm());
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
	protected void validateKey(Key key)
			throws UnsupportedKeySizeException, UnsupportedAlgorithmException {
		byte[] keyBytes = key.getEncoded();
		// Validate Key Size for AES
		if (keyBytes.length != 16 && keyBytes.length != 24
				&& keyBytes.length != 32) {
			throw new UnsupportedKeySizeException(
					"Found unsupported key size ["
							+ (keyBytes.length * 8)
							+ "]. The AES algorithm only supports key sizes of 128, 192, or 256");
		}

		if (!"AES".equals(key.getAlgorithm())) {
			throw new UnsupportedAlgorithmException(
					"Key does not support AES algorithm: ["
							+ key.getAlgorithm() + "]");
		}

	}

}
