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
package net.theblackchamber.util;

import static org.junit.Assert.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStoreException;
import java.util.Properties;

import net.theblackchamber.crypto.constants.Constants;
import net.theblackchamber.crypto.constants.SupportedKeyGenAlgorithms;
import net.theblackchamber.crypto.exceptions.RuntimeCryptoException;
import net.theblackchamber.crypto.implementations.SecureProperties;
import net.theblackchamber.crypto.model.KeyConfig;
import net.theblackchamber.crypto.util.KeystoreUtils;
import net.theblackchamber.crypto.util.SecurePropertiesUtils;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class SecurePropertiesUtilsTest {

	@ClassRule
	public static TemporaryFolder temporaryFolder = new TemporaryFolder();

	@Rule
	public TemporaryFolder tempPropertiesFolder = new TemporaryFolder();

	@BeforeClass
	public static void init() {
		try {
			File keyfile = temporaryFolder.newFile("test.key");

			assertTrue(keyfile.exists());
			KeyConfig config = new KeyConfig(keyfile, "TEST", null,
					SupportedKeyGenAlgorithms.AES, "aes-key");
			KeystoreUtils.generateSecretKey(config);
		} catch (Throwable t) {
			t.printStackTrace();
			fail();
		}
	}

	@Test
	public void testEncryptPropertiesFileParameterConfigDontKeepConfigMissingParams() {
		try {
			File keyfile = new File(temporaryFolder.getRoot().getPath()
					+ File.separator + "test.key");

			File propertiesFile = writeTestFile(keyfile, false, false, false);

			try {
				SecurePropertiesUtils.encryptPropertiesFile(propertiesFile,keyfile.getPath(), "TEST", null);
			} catch (KeyStoreException kse) {
				// This was intended
			}

			try {
				SecurePropertiesUtils.encryptPropertiesFile(propertiesFile,keyfile.getPath(), null, "aes-key");
			} catch (KeyStoreException kse) {
				// This was intended
			}

			try {
				SecurePropertiesUtils.encryptPropertiesFile(propertiesFile,null, "TEST", "aes-key");
			} catch (KeyStoreException kse) {
				// This was intended
			}

		} catch (Throwable t) {
			t.printStackTrace();
			fail();
		}
	}

	@Test
	public void testEncryptPropertiesFileParameterConfigKeepConfigMissingParams() {
		try {
			File keyfile = new File(temporaryFolder.getRoot().getPath()
					+ File.separator + "test.key");

			File propertiesFile = writeTestFile(keyfile, false, false, false);

			try {
				SecurePropertiesUtils.encryptPropertiesFile(propertiesFile,keyfile.getPath(), "TEST", null,true);
			} catch (KeyStoreException kse) {
				// This was intended
			}

			try {
				SecurePropertiesUtils.encryptPropertiesFile(propertiesFile,keyfile.getPath(), null, "aes-key",true);
			} catch (KeyStoreException kse) {
				// This was intended
			}

			try {
				SecurePropertiesUtils.encryptPropertiesFile(propertiesFile,null, "TEST", "aes-key",true);
			} catch (KeyStoreException kse) {
				// This was intended
			}

		} catch (Throwable t) {
			t.printStackTrace();
			fail();
		}
	}
	
	//Test encrypting properties file where encryption configuration is passed in by parameter. Configuration from parameters will not be stored in the final properties file
	@Test
	public void testEncryptPropertiesFileParameterConfigDontKeepConfig() {
		
		try{
		
		File keyfile = new File(temporaryFolder.getRoot().getPath()
				+ File.separator + "test.key");

		File propertiesFile = writeTestFile(keyfile, false, false, false);
		
		SecureProperties sProperties = SecurePropertiesUtils.encryptPropertiesFile(propertiesFile, keyfile.getPath(),"TEST", "aes-key");
		String decryptedProperty = sProperties.getProperty("test-encrypted");
		assertTrue(StringUtils.equals(decryptedProperty, "TESTY"));
		assertTrue(sProperties.getProperty("test-unencrypted") == null);

		sProperties = new SecureProperties();
		InputStream is = new FileInputStream(propertiesFile);
		sProperties.load(is);
		assertFalse(sProperties.containsKey(Constants.ENTRY_NAME_PROPERTY_KEY));
		assertFalse(sProperties.containsKey(Constants.KEYSTORE_PASSWORD_PROPERTY_KEY));
		assertFalse(sProperties.containsKey(Constants.KEY_PATH_PROPERTY_KEY));
		
		try{
			sProperties.getProperty("test-encrypted");
			fail();
		}catch(RuntimeCryptoException rce){
			//Expected
		}
		
		
		} catch (Throwable t) {
			t.printStackTrace();
			fail();
		}
		
	}
	
	//Test encrypting properties file where encryption configuration is passed in by parameter. Configuration from parameters will be stored in the final properties file
		@Test
		public void testEncryptPropertiesFileParameterConfigKeepConfig() {
			
			try{
			
			File keyfile = new File(temporaryFolder.getRoot().getPath()
					+ File.separator + "test.key");

			File propertiesFile = writeTestFile(keyfile, false, false, false);
			
			SecureProperties sProperties = SecurePropertiesUtils.encryptPropertiesFile(propertiesFile, keyfile.getPath(),"TEST", "aes-key",true);
			String decryptedProperty = sProperties.getProperty("test-encrypted");
			assertTrue(StringUtils.equals(decryptedProperty, "TESTY"));
			assertTrue(sProperties.getProperty("test-unencrypted") == null);

			sProperties = new SecureProperties();
			InputStream is = new FileInputStream(propertiesFile);
			sProperties.load(is);
			assertTrue(sProperties.containsKey(Constants.ENTRY_NAME_PROPERTY_KEY));
			assertTrue(sProperties.containsKey(Constants.KEYSTORE_PASSWORD_PROPERTY_KEY));
			assertTrue(sProperties.containsKey(Constants.KEY_PATH_PROPERTY_KEY));
			
			decryptedProperty = sProperties.getProperty("test-encrypted");
			assertTrue(StringUtils.equals(decryptedProperty, "TESTY"));
			
			
			} catch (Throwable t) {
				t.printStackTrace();
				fail();
			}
			
		}
	
	//Test encrypting properties file where the properties file contains all the information needed to configure crypto
	@Test
	public void testEncryptPropertiesFilePropertyConfig() {
		try {
			File keyfile = new File(temporaryFolder.getRoot().getPath()
					+ File.separator + "test.key");

			File propertiesFile = writeTestFile(keyfile, true, true, true);

			SecureProperties sProperties = SecurePropertiesUtils.encryptPropertiesFile(propertiesFile);
			String decryptedProperty = sProperties.getProperty("test-encrypted");
			assertTrue(StringUtils.equals(decryptedProperty, "TESTY"));
			assertTrue(sProperties.getProperty("test-unencrypted") == null);

			sProperties = new SecureProperties();
			InputStream is = new FileInputStream(propertiesFile);
			sProperties.load(is);
			decryptedProperty = sProperties.getProperty("test-encrypted");
			assertTrue(StringUtils.equals(decryptedProperty, "TESTY"));
			assertTrue(sProperties.getProperty("test-unencrypted") == null);

		} catch (Throwable t) {
			t.printStackTrace();
			fail();
		}
	}

	private File writeTestFile(File keyfile, boolean pass, boolean entryname,
			boolean keypath) throws IOException {
		Properties clearProperties = new Properties();

		if (keypath) {
			clearProperties.setProperty("key-path", keyfile.getPath());
		}
		if (entryname) {
			clearProperties.setProperty("entry-name", "aes-key");
		}
		if (pass) {
			clearProperties.setProperty("keystore-password", "TEST");
		}
		clearProperties.setProperty("test-unencrypted", "TESTY");

		File propertiesFile = tempPropertiesFolder.newFile("test.properties");
		OutputStream stream = new FileOutputStream(propertiesFile);
		clearProperties.store(stream, "comment");
		stream.close();
		assertTrue(propertiesFile.exists());
		assertTrue(FileUtils.sizeOf(keyfile) > 0);

		return propertiesFile;

	}

}
