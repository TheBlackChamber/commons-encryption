package net.theblackchamber.util;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Properties;

import javax.crypto.SecretKey;

import net.theblackchamber.crypto.constants.SupportedAlgorithms;
import net.theblackchamber.crypto.implementations.SecureProperties;
import net.theblackchamber.crypto.model.KeyConfig;
import net.theblackchamber.crypto.providers.AESEncryptionProvider;
import net.theblackchamber.crypto.util.KeystoreUtils;
import net.theblackchamber.crypto.util.SecurePropertiesUtils;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class SecurePropertiesUtilsTest {

	@Rule
	public TemporaryFolder temporaryFolder = new TemporaryFolder();
	
	@Test
	public void testEncryptPropertiesFile(){
		try{
			File keyfile = temporaryFolder.newFile("test.key");
			
			assertTrue(keyfile.exists());
			KeyConfig config = new KeyConfig(keyfile, "TEST", null, SupportedAlgorithms.AES, "aes-key");
			KeystoreUtils.generateAESSecretKey(config);
			
			Properties clearProperties = new Properties();
			clearProperties.setProperty("key-path", keyfile.getPath());
			clearProperties.setProperty("entry-name", "aes-key");
			clearProperties.setProperty("keystore-password", "TEST");
			clearProperties.setProperty("test-unencrypted", "TESTY");
			
			File propertiesFile = temporaryFolder.newFile("test.properties");
			OutputStream stream = new FileOutputStream(propertiesFile);
			clearProperties.store(stream, "comment");
			stream.close();
			assertTrue(propertiesFile.exists());
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
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
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	
}
