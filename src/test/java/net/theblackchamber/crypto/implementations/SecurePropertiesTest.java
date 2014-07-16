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
package net.theblackchamber.crypto.implementations;

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
import net.theblackchamber.crypto.model.KeyConfig;
import net.theblackchamber.crypto.providers.AESEncryptionProvider;
import net.theblackchamber.crypto.util.KeystoreUtils;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class SecurePropertiesTest {

	@Rule
	public TemporaryFolder temporaryFolder = new TemporaryFolder();
	
	@Test
	public void testSecurePropertiesIsProperties(){
		try{
			
			Properties properties = new SecureProperties();
			
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
			KeyConfig config = new KeyConfig(keyfile, "TEST", null, SupportedAlgorithms.AES, "aes-key");
			KeystoreUtils.generateAESSecretKey(config);
		
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			Properties props = new SecureProperties();
			props.setProperty("entry-name", "aes-key");
			props.setProperty("keystore-password", "TEST");
			props.setProperty("key-path", keyfile.getPath());
			
			assertNotNull(((SecureProperties)props).getKey());
			assertNotNull(((SecureProperties)props).getEncryptionProvider());
			
			assertTrue(StringUtils.equals(props.getProperty("key-path"), keyfile.getPath()));
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testCreateNewSecurePropertiesFromPropertiesUsingParamsConstructor(){
		try{
			
			File keyfile = temporaryFolder.newFile("test.key");
		
			assertTrue(keyfile.exists());
			KeyConfig config = new KeyConfig(keyfile, "TEST", null, SupportedAlgorithms.AES, "aes-key");
			KeystoreUtils.generateAESSecretKey(config);
		
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			Properties clearProperties = new Properties();
			
			Properties props = new SecureProperties(clearProperties,keyfile.getPath(),"aes-key","TEST");
			
			assertNotNull(((SecureProperties)props).getKey());
			assertNotNull(((SecureProperties)props).getEncryptionProvider());
			
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
			KeyConfig config = new KeyConfig(keyfile, "TEST", null, SupportedAlgorithms.AES, "aes-key");
			KeystoreUtils.generateAESSecretKey(config);
		
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			Properties clearProperties = new Properties();
			clearProperties.setProperty("key-path", keyfile.getPath());
			clearProperties.setProperty("entry-name", "aes-key");
			clearProperties.setProperty("keystore-password", "TEST");
			
			
			Properties props = new SecureProperties(clearProperties);
			
			assertNotNull(((SecureProperties)props).getKey());
			assertNotNull(((SecureProperties)props).getEncryptionProvider());
			
			assertTrue(StringUtils.equals(props.getProperty("key-path"), keyfile.getPath()));
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testCreateNewSecurePropertiesFromInputStream(){
		try{
			
			File keyfile = temporaryFolder.newFile("test.key");
			
			assertTrue(keyfile.exists());
			KeyConfig config = new KeyConfig(keyfile, "TEST", null, SupportedAlgorithms.AES, "aes-key");
			KeystoreUtils.generateAESSecretKey(config);
		
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			Properties clearProperties = new Properties();
			clearProperties.setProperty("key-path", keyfile.getPath());
			clearProperties.setProperty("entry-name", "aes-key");
			clearProperties.setProperty("keystore-password", "TEST");
			
			File propertiesFile = temporaryFolder.newFile("test.properties");
			OutputStream stream = new FileOutputStream(propertiesFile);
			clearProperties.store(stream, "comment");
			stream.close();
			assertTrue(propertiesFile.exists());
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			InputStream inputStream = new FileInputStream(propertiesFile);
			SecureProperties sProperties = new SecureProperties();
			sProperties.load(inputStream);
			assertNotNull(sProperties);
			assertNotNull(sProperties.getProperty("entry-name"));
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testLoadSecurePropertiesFromFile(){
		try{
			File keyfile = temporaryFolder.newFile("test.key");
			
			assertTrue(keyfile.exists());
			KeyConfig config = new KeyConfig(keyfile, "TEST", null, SupportedAlgorithms.AES, "aes-key");
			KeystoreUtils.generateAESSecretKey(config);
			SecretKey key = KeystoreUtils.getAESSecretKey(keyfile, "aes-key", "TEST");
			
			AESEncryptionProvider encryptionProvider = new AESEncryptionProvider(key);
			
			Properties clearProperties = new Properties();
			clearProperties.setProperty("key-path", keyfile.getPath());
			clearProperties.setProperty("entry-name", "aes-key");
			clearProperties.setProperty("keystore-password", "TEST");
			clearProperties.setProperty("test-encrypted", encryptionProvider.encrypt("TESTY"));
			
			File propertiesFile = temporaryFolder.newFile("test.properties");
			OutputStream stream = new FileOutputStream(propertiesFile);
			clearProperties.store(stream, "comment");
			stream.close();
			assertTrue(propertiesFile.exists());
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			FileReader reader = new FileReader(propertiesFile);
			SecureProperties sProperties = new SecureProperties();
			sProperties.load(reader);
			assertNotNull(sProperties);
			String decryptedProperty = sProperties.getProperty("test-encrypted");
			assertTrue(StringUtils.equals(decryptedProperty, "TESTY"));
			
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testCreateNewSecurePropertiesFromReader(){
		try{
			
			File keyfile = temporaryFolder.newFile("test.key");
			
			assertTrue(keyfile.exists());
			KeyConfig config = new KeyConfig(keyfile, "TEST", null, SupportedAlgorithms.AES, "aes-key");
			KeystoreUtils.generateAESSecretKey(config);
		
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			Properties clearProperties = new Properties();
			clearProperties.setProperty("key-path", keyfile.getPath());
			clearProperties.setProperty("entry-name", "aes-key");
			clearProperties.setProperty("keystore-password", "TEST");
			
			File propertiesFile = temporaryFolder.newFile("test.properties");
			OutputStream stream = new FileOutputStream(propertiesFile);
			clearProperties.store(stream, "comment");
			stream.close();
			assertTrue(propertiesFile.exists());
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			FileReader reader = new FileReader(propertiesFile);
			SecureProperties sProperties = new SecureProperties();
			sProperties.load(reader);
			assertNotNull(sProperties);
			assertNotNull(sProperties.getProperty("entry-name"));
			assertNotNull(sProperties.getProperty("nothere","TEST"));
			assertTrue(!StringUtils.equals(sProperties.getProperty("entry-name","SM"), "SM"));
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testCreateNewSecurePropertiesFromXml(){
		try{
			
			File keyfile = temporaryFolder.newFile("test.key");
			
			assertTrue(keyfile.exists());
			KeyConfig config = new KeyConfig(keyfile, "TEST", null, SupportedAlgorithms.AES, "aes-key");
			KeystoreUtils.generateAESSecretKey(config);
		
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			Properties clearProperties = new Properties();
			clearProperties.setProperty("key-path", keyfile.getPath());
			clearProperties.setProperty("entry-name", "aes-key");
			clearProperties.setProperty("keystore-password", "TEST");
			
			File propertiesFile = temporaryFolder.newFile("test.xml");
			OutputStream stream = new FileOutputStream(propertiesFile);
			clearProperties.storeToXML(stream, "comment");
			stream.close();
			assertTrue(propertiesFile.exists());
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			InputStream is = new FileInputStream(propertiesFile);
			SecureProperties sProperties = new SecureProperties();
			sProperties.loadFromXML(is);
			assertNotNull(sProperties);
			assertNotNull(sProperties.getProperty("entry-name"));
			
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
			KeyConfig config = new KeyConfig(keyfile, "TEST", null, SupportedAlgorithms.AES, "aes-key");
			KeystoreUtils.generateAESSecretKey(config);
		
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			Properties props = new SecureProperties();
			props.setProperty("entry-name", "aes-key");
			props.setProperty("keystore-password", "TEST");
			props.setProperty("key-path", keyfile.getPath());
			
			
			assertNotNull(((SecureProperties)props).getKey());
			assertNotNull(((SecureProperties)props).getEncryptionProvider());
			
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
			KeyConfig config = new KeyConfig(keyfile, "TEST", null, SupportedAlgorithms.AES, "aes-key");
			KeystoreUtils.generateAESSecretKey(config);
		
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			Properties props = new SecureProperties();
			props.setProperty("test", "test");
			
			assertTrue(StringUtils.equals("test", props.getProperty("test")));
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
}
