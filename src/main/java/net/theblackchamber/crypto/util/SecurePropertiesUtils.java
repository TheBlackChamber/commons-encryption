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
package net.theblackchamber.crypto.util;

import static net.theblackchamber.crypto.constants.Constants.ENTRY_NAME_PROPERTY_KEY;
import static net.theblackchamber.crypto.constants.Constants.KEYSTORE_PASSWORD_PROPERTY_KEY;
import static net.theblackchamber.crypto.constants.Constants.KEY_PATH_PROPERTY_KEY;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStoreException;
import java.util.Properties;

import net.theblackchamber.crypto.implementations.SecureProperties;

import org.apache.commons.lang3.StringUtils;

/**
 * Utility class to provide an easy way to take a clear text properties file and
 * encrypt it.
 * 
 * @author sminogue
 * 
 */
public class SecurePropertiesUtils {

	/**
	 * Utility which will take an existing Properties file on disk and replace
	 * any -unencrypted values with encrypted.<br>
	 * NOTE: The encryption related properties need to be properly set prior to
	 * using this. entry-name, key-path, keystore-password
	 * 
	 * @param clearProperties
	 * @return
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws KeyStoreException
	 */
	public static SecureProperties encryptPropertiesFile(File clearProperties)
			throws FileNotFoundException, IOException, KeyStoreException {

		// Save filename/Path
		String propertiesFilePath = clearProperties.getPath();

		// Create new SecureProperties
		SecureProperties sProperties = new SecureProperties();

		// Open clear properties file and load it
		Properties cProperties = new Properties();
		FileInputStream fis = new FileInputStream(clearProperties);
		cProperties.load(fis);
		fis.close();

		// Ensure properties contains fields defining encryption
		if (!cProperties.containsKey(ENTRY_NAME_PROPERTY_KEY)
				|| !cProperties.containsKey(KEY_PATH_PROPERTY_KEY)
				|| !cProperties.containsKey(KEYSTORE_PASSWORD_PROPERTY_KEY)) {
			throw new KeyStoreException(
					"Unable to configure due to missing configurations");
		}

		// Loop over clear properties and construct new SecureProperties object
		// First add crypto entries this will initialize the encryption support.
		sProperties.setProperty(ENTRY_NAME_PROPERTY_KEY,
				cProperties.getProperty(ENTRY_NAME_PROPERTY_KEY));
		sProperties.setProperty(KEYSTORE_PASSWORD_PROPERTY_KEY,
				cProperties.getProperty(KEYSTORE_PASSWORD_PROPERTY_KEY));
		sProperties.setProperty(KEY_PATH_PROPERTY_KEY,
				cProperties.getProperty(KEY_PATH_PROPERTY_KEY));

		for (Object key : cProperties.keySet()) {

			String keyStr = (String) key;
			if (!StringUtils.equals(keyStr, ENTRY_NAME_PROPERTY_KEY)
					&& !StringUtils.equals(keyStr,
							KEYSTORE_PASSWORD_PROPERTY_KEY)
					&& !StringUtils.equals(keyStr, KEY_PATH_PROPERTY_KEY)) {
				sProperties
						.setProperty(keyStr, cProperties.getProperty(keyStr));
			}

		}

		// Delete original file from disk
		clearProperties.delete();

		// Write SecureProperties out in its place
		OutputStream fos = new FileOutputStream(new File(propertiesFilePath));
		sProperties.store(fos, "File Encrypted by SecurePropertiesUtils");
		fos.flush();
		fos.close();

		// Return completed SecureProperties object
		return sProperties;

	}

}
