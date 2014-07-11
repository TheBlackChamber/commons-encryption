package net.theblackchamber.crypto.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStoreException;
import java.util.Properties;

import org.apache.commons.lang3.StringUtils;

import static net.theblackchamber.crypto.constants.Constants.*;
import net.theblackchamber.crypto.implementations.SecureProperties;

public class SecurePropertiesUtils {

	/**
	 * Utility which will take an existing Properties file on disk and replace
	 * any -unencrypted values with encrypted.
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
