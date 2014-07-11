/**
 * The MIT License (MIT)
 *
 * Copyright (c) {{{year}}} {{{fullname}}}
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

import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.SimplePBEConfig;
import org.jasypt.salt.RandomSaltGenerator;

public class AESEncryptionProvider {

	private SecretKey key;
	StandardPBEStringEncryptor encryptor;

	public AESEncryptionProvider(final SecretKey key) {
		super();
		this.key = key;

		// Configure Encryptor
		SimplePBEConfig config = new SimplePBEConfig();
		config.setAlgorithm("PBEWITHSHA256AND128BITAES-CBC-BC");
		config.setKeyObtentionIterations(10);
		config.setPassword(Hex.toHexString(key.getEncoded()));
		config.setProvider(new BouncyCastleProvider());
		config.setSaltGenerator(new RandomSaltGenerator());

		encryptor = new StandardPBEStringEncryptor();
		encryptor.setConfig(config);
		encryptor.setStringOutputType("hexadecimal");
	}

	public String decrypt(String cipherText) {
		return encryptor.decrypt(cipherText);
	}

	public String encrypt(String clearText) {
		return encryptor.encrypt(clearText);
	}

}
