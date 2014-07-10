package net.theblackchamber.crypto.providers;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Properties;

import javax.crypto.SecretKey;

import net.theblackchamber.crypto.util.KeystoreUtils;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.Rule;
import org.junit.Test;

import static org.junit.Assert.*;

import org.junit.rules.TemporaryFolder;

public class SecurePropertiesProviderTest {

	@Rule
	public TemporaryFolder temporaryFolder = new TemporaryFolder();
	
	@Test
	public void testSecurePropertiesIsProperties(){
		try{
			
			Properties properties = new SecurePropertiesProvider();
			
			assertNotNull(properties);
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testCreateNewSecurePropertiesFromNothing(){
		try{
		
			File keyfile = temporaryFolder.newFile("test.key");
		
			assertTrue(keyfile.exists());
			
			KeystoreUtils.generateAESSecretKey(keyfile);
		
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			Properties props = new SecurePropertiesProvider();
			
			props.setProperty("key-path", keyfile.getPath());
			
			assertNotNull(((SecurePropertiesProvider)props).getKey());
			assertNotNull(((SecurePropertiesProvider)props).getEncryptionProvider());
			
			assertTrue(StringUtils.equals(props.getProperty("key-path"), keyfile.getPath()));
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testCreateNewSecurePropertiesFromProperties(){
		try{
		
			File keyfile = temporaryFolder.newFile("test.key");
		
			assertTrue(keyfile.exists());
			
			KeystoreUtils.generateAESSecretKey(keyfile);
		
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			Properties clearProperties = new Properties();
			clearProperties.setProperty("key-path", keyfile.getPath());
			
			Properties props = new SecurePropertiesProvider(clearProperties);
			
			assertNotNull(((SecurePropertiesProvider)props).getKey());
			assertNotNull(((SecurePropertiesProvider)props).getEncryptionProvider());
			
			assertTrue(StringUtils.equals(props.getProperty("key-path"), keyfile.getPath()));
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testEncryptSetProperties(){
		try{
			File keyfile = temporaryFolder.newFile("test.key");
			
			assertTrue(keyfile.exists());
			
			KeystoreUtils.generateAESSecretKey(keyfile);
		
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			Properties props = new SecurePropertiesProvider();
			
			props.setProperty("key-path", keyfile.getPath());
			
			assertNotNull(((SecurePropertiesProvider)props).getKey());
			assertNotNull(((SecurePropertiesProvider)props).getEncryptionProvider());
			
			assertTrue(StringUtils.equals(props.getProperty("key-path"), keyfile.getPath()));
			
			String clearString = "TEST";
			props.setProperty("test-unencrypted", clearString);
			
			assertTrue(StringUtils.equals(clearString, props.getProperty("test-encrypted")));
			assertTrue(!StringUtils.equals(clearString, (String)props.get("test-encrypted")));
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testClearSetProperties(){
		try{
			File keyfile = temporaryFolder.newFile("test.key");
			
			assertTrue(keyfile.exists());
			
			KeystoreUtils.generateAESSecretKey(keyfile);
		
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			Properties props = new SecurePropertiesProvider();
			props.setProperty("test", "test");
			
			assertTrue(StringUtils.equals("test", props.getProperty("test")));
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	private Properties createTestCipherProperties(String keyPath) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, UnrecoverableEntryException, IOException{
		
		SecretKey key = KeystoreUtils.getAESSecretKey(new File(keyPath));
		AESEncryptionProvider encryptionProvider = new AESEncryptionProvider(key);
		
		Properties props = createTestClearProperties(keyPath);
		String cipherTestText = encryptionProvider.encrypt("TEST");
		props.setProperty("test-encrypted", cipherTestText);
		
		return props;
		
	}
	
	private Properties createTestClearProperties(String keyPath){
		
		Properties properties = new Properties();
		
		properties.setProperty("key-path", keyPath);
		properties.setProperty("test", "test");
		
		return properties;
		
	}
	
}
