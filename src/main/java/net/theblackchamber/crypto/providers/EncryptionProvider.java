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

/**
 * Abstract class which will be the base for all Encryption providers. This is
 * kinda un-needed at the moment but I am adding it to support future plans to
 * allow more dynamic configuration of encryption used in utilities.
 * 
 * @author sminogue
 * 
 */
public abstract class EncryptionProvider<T> {

	/**
	 * Encryption {@link Key} to be used for encryption and decryption options.
	 */
	private T key;
	
	/**
	 * Method which will return the {@link Key} being used by the instance of this provider.
	 * @return
	 */
	protected T getKey(){
		return key;
	}
	
	/**
	 * Method which will set the {@link Key} to be used by the instance of this provider.
	 * @param key
	 */
	protected void setKey(final T key){
		this.key = key;
	}
	
	/**
	 * Method which will decrypt a string.
	 * 
	 * @param cipherText
	 * @return
	 */
	public abstract String decrypt(String cipherText);

	/**
	 * Method which will encrypt a string.
	 * 
	 * @param clearText
	 * @return
	 */
	public abstract String encrypt(String clearText);

}
