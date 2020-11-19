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
package net.theblackchamber.crypto.providers.digest;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.digest.config.SimpleDigesterConfig;
import org.jasypt.salt.RandomSaltGenerator;
import org.jasypt.util.password.ConfigurablePasswordEncryptor;

/**
 * Class which will provide the means of hashing data using SHA256
 * @author sminogue
 *
 */
public class SHA256DigestProvider {

	public static enum TYPE {
		
		SHA1("SHA-1"),SHA256("SHA-256"),SHA384("SHA-384"),SHA512("SHA-512");

		String value;
		
		TYPE(String string) {
			this.value  = string;
		}
		
		String getValue() {
			return value;
		}
		
	}
	
	private ConfigurablePasswordEncryptor encryptor;
	
	/**
	 * Constructor
	 */
	public SHA256DigestProvider(TYPE type) {
		
		SimpleDigesterConfig config = new SimpleDigesterConfig();
		config.setAlgorithm(type.getValue());
		config.setIterations(50000);
		config.setProvider(new BouncyCastleProvider());
		
		encryptor = new ConfigurablePasswordEncryptor();
		encryptor.setProvider(new BouncyCastleProvider());
		encryptor.setAlgorithm(type.getValue());
		encryptor.setConfig(config);
		encryptor.setPlainDigest(true);
		encryptor.setStringOutputType("hexadecimal");
		
	}

	/**
	 * Perform hash/digest of string.
	 * @param clear
	 * @return HEX String of hashed data
	 */
	public String digest(String clear){
		
		return encryptor.encryptPassword(clear);
		
	}
	
}
