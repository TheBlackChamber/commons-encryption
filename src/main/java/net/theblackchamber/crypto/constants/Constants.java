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
package net.theblackchamber.crypto.constants;

import java.security.KeyStore;

/**
 * Class which will define all constants used across classes. Classes MAY
 * contain private constants but anything which is used across classes will be
 * defined here.
 * 
 * @author sminogue
 * 
 */
public class Constants {
	/**
	 * ======================================================
	 * Constants Used by the {@link SecureProperties} classes
	 * ======================================================
	 */
	/**
	 * Property key which defines the {@link KeyStore} entry to be used.
	 */
	public static final String ENTRY_NAME_PROPERTY_KEY = "entry-name";
	/**
	 * Property key which defines the file path to the {@link KeyStore} to be loaded from file.
	 */
	public static final String KEY_PATH_PROPERTY_KEY = "key-path";
	/**
	 * Property key which defines the password to be used to open the {@link KeyStore}
	 */
	public static final String KEYSTORE_PASSWORD_PROPERTY_KEY = "keystore-password";

}
