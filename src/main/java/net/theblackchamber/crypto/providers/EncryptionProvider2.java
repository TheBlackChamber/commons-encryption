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
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import org.apache.commons.lang3.StringUtils;

import com.google.crypto.tink.KeysetHandle;

import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import net.theblackchamber.crypto.exceptions.MissingParameterException;

/**
 * Abstract class which will be the base for all Encryption providers. This is
 * kinda un-needed at the moment but I am adding it to support future plans to
 * allow more dynamic configuration of encryption used in utilities.
 * 
 * @author sminogue
 * 
 */
@Getter
@RequiredArgsConstructor
public abstract class EncryptionProvider2 {

	/**
	 * Encryption {@link KeysetHandle} to be used for encryption and decryption
	 * options.
	 */
	@NonNull
	private KeysetHandle key;

	Encoder encoder = Base64.getEncoder();
	Decoder decoder = Base64.getDecoder();
	
	protected abstract byte[] performEncryption(byte[] data, byte[] associated) throws GeneralSecurityException;
	protected abstract byte[] performDecryption(byte[] data, byte[] associated) throws GeneralSecurityException;

	/**
	 * Method which will decrypt a string.
	 * 
	 * @param cipherText Encrypted text to be decrypted.
	 * @return
	 * @throws MissingParameterException
	 * @throws GeneralSecurityException
	 */
	public String decrypt(String cipherText, String associated)
			throws MissingParameterException, GeneralSecurityException {

		if (StringUtils.isBlank(cipherText)) {
			throw new MissingParameterException("Missing parameter: cipherText");
		}
		return new String(performDecryption(decoder.decode(cipherText), associated.getBytes()));
	}

	/**
	 * Method which will decrypt a string.
	 * 
	 * @param cipherText Encrypted text to be decrypted.
	 * @return
	 * @throws MissingParameterException
	 * @throws GeneralSecurityException
	 */
	public String decrypt(String cipherText) throws MissingParameterException, GeneralSecurityException {
		return decrypt(cipherText, "");
	}

	/**
	 * Method which will encrypt a string.
	 * 
	 * @param clearText Clear text to be encrypted.
	 * @return Encrypted text.
	 * @throws MissingParameterException
	 * @throws GeneralSecurityException
	 */
	public String encrypt(String clearText, String associated)
			throws MissingParameterException, GeneralSecurityException {

		if (StringUtils.isBlank(clearText)) {
			throw new MissingParameterException("Missing parameter: clearText");
		}

		return encoder.encodeToString(performEncryption(clearText.getBytes(), associated.getBytes()));

	}

	public byte[] encrypt(byte[] clearText, byte[] associated)
			throws MissingParameterException, GeneralSecurityException {

		if (clearText == null || clearText.length == 0) {
			throw new MissingParameterException("Missing parameter: clearText");
		}

		if(associated == null) {
			associated = new byte[0];
		}
		
		return performEncryption(clearText, associated);

	}
	
	public byte[] encrypt(byte[] clearText)
			throws MissingParameterException, GeneralSecurityException {

		if (clearText == null || clearText.length == 0) {
			throw new MissingParameterException("Missing parameter: clearText");
		}

		return performEncryption(clearText, null);

	}
	
	public byte[] decrypt(byte[] cipherText, byte[] associated)
			throws MissingParameterException, GeneralSecurityException {

		if (cipherText == null || cipherText.length == 0) {
			throw new MissingParameterException("Missing parameter: cipherText");
		}

		if(associated == null) {
			associated = new byte[0];
		}
		
		return performDecryption(cipherText, associated);

	}
	
	public byte[] decrypt(byte[] cipherText)
			throws MissingParameterException, GeneralSecurityException {

		if (cipherText == null || cipherText.length == 0) {
			throw new MissingParameterException("Missing parameter: cipherText");
		}

		return performDecryption(cipherText, null);

	}
	
	/**
	 * Method which will encrypt a string.
	 * 
	 * @param clearText Clear text to be encrypted.
	 * @return Encrypted text.
	 * @throws MissingParameterException
	 * @throws GeneralSecurityException
	 */
	public String encrypt(String clearText) throws MissingParameterException, GeneralSecurityException {

		return encrypt(clearText, "");

	}

}
