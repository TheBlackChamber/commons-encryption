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

import net.theblackchamber.crypto.constants.Constants;
import net.theblackchamber.crypto.constants.SupportedKeyGenAlgorithms;
import net.theblackchamber.crypto.model.KeyConfig;
import net.theblackchamber.crypto.model.KeyConfig2;
import net.theblackchamber.crypto.providers.EncryptionProvider2;
import net.theblackchamber.crypto.providers.EncryptionProviderFactory2;
import net.theblackchamber.crypto.providers.symmetric.AESEncryptionProvider;
import net.theblackchamber.crypto.providers.symmetric.AESEncryptionProvider2;
import net.theblackchamber.crypto.util.KeystoreUtils;
import net.theblackchamber.crypto.util.KeystoreUtils2;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.google.crypto.tink.KeysetHandle;

public class SecurePropertiesAESTest2 {

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
			KeyConfig2 config = new KeyConfig2(keyfile);
			KeystoreUtils2.generateSecretKey(config);
		
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			Properties props = new SecureProperties2();
			props.setProperty("key-path", keyfile.getPath());
			
			assertNotNull(((SecureProperties2)props).getKey());
			assertNotNull(((SecureProperties2)props).getEncryptionProvider());
			
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
			KeyConfig2 config = new KeyConfig2(keyfile);
			KeystoreUtils2.generateSecretKey(config);
		
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			Properties clearProperties = new Properties();
			
			Properties props = new SecureProperties2(clearProperties,keyfile.getPath());
			
			assertNotNull(((SecureProperties2)props).getKey());
			assertNotNull(((SecureProperties2)props).getEncryptionProvider());
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testCreateNewSecurePropertiesFromPropertiesUsingParamsConstructorNullPass(){
		try{
			
			File keyfile = temporaryFolder.newFile("test.key");
		
			assertTrue(keyfile.exists());
			KeyConfig2 config = new KeyConfig2(keyfile);
			KeystoreUtils2.generateSecretKey(config);
		
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			Properties clearProperties = new Properties();
			Properties props = new SecureProperties2(clearProperties,keyfile.getPath());
			
			assertNotNull(((SecureProperties2)props).getKey());
			assertNotNull(((SecureProperties2)props).getEncryptionProvider());
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testCreateNewSecurePropertiesFromPropertiesUsingParamsConstructorNullEntry(){
		try{
			
			File keyfile = temporaryFolder.newFile("test.key");
		
			assertTrue(keyfile.exists());
			KeyConfig2 config = new KeyConfig2(keyfile);
			KeystoreUtils2.generateSecretKey(config);
		
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			Properties clearProperties = new Properties();
			clearProperties.setProperty(Constants.ENTRY_NAME_PROPERTY_KEY, "aes-key");
			
			Properties props = new SecureProperties2(clearProperties,keyfile.getPath());
			
			assertNotNull(((SecureProperties2)props).getKey());
			assertNotNull(((SecureProperties2)props).getEncryptionProvider());
			
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
			KeyConfig2 config = new KeyConfig2(keyfile);
			KeystoreUtils2.generateSecretKey(config);
		
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			Properties clearProperties = new Properties();
			clearProperties.setProperty("key-path", keyfile.getPath());
			clearProperties.setProperty("entry-name", "aes-key");
			clearProperties.setProperty("keystore-password", "TEST");
			
			
			Properties props = new SecureProperties2(clearProperties);
			
			assertNotNull(((SecureProperties2)props).getKey());
			assertNotNull(((SecureProperties2)props).getEncryptionProvider());
			
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
			KeyConfig2 config = new KeyConfig2(keyfile);
			KeystoreUtils2.generateSecretKey(config);
		
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
			SecureProperties2 sProperties = new SecureProperties2();
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
			KeyConfig2 config = new KeyConfig2(keyfile);
			KeystoreUtils2.generateSecretKey(config);
			KeysetHandle key = KeystoreUtils2.getSecretKey(keyfile);
			
			EncryptionProvider2 encryptionProvider = EncryptionProviderFactory2.getProvider(key);
			
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
			SecureProperties2 sProperties = new SecureProperties2();
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
	public void testLoadSecurePropertiesFromFileConstructor(){
		try{
			File keyfile = temporaryFolder.newFile("test.key");
			
			assertTrue(keyfile.exists());
			KeyConfig2 config = new KeyConfig2(keyfile);
			KeystoreUtils2.generateSecretKey(config);
			KeysetHandle key = KeystoreUtils2.getSecretKey(keyfile);
			
			EncryptionProvider2 encryptionProvider = EncryptionProviderFactory2.getProvider(key);
			
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
			
			SecureProperties2 sProperties = new SecureProperties2(propertiesFile);
			assertNotNull(sProperties);
			String decryptedProperty = sProperties.getProperty("test-encrypted");
			assertTrue(StringUtils.equals(decryptedProperty, "TESTY"));
			
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testLoadSecurePropertiesFromPath(){
		try{
			File keyfile = temporaryFolder.newFile("test.key");
			
			assertTrue(keyfile.exists());
			KeyConfig2 config = new KeyConfig2(keyfile);
			KeystoreUtils2.generateSecretKey(config);
			KeysetHandle key = KeystoreUtils2.getSecretKey(keyfile);
			
			EncryptionProvider2 encryptionProvider = EncryptionProviderFactory2.getProvider(key);
			
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
			
			SecureProperties2 sProperties = new SecureProperties2(propertiesFile.getPath());
			assertNotNull(sProperties);
			String decryptedProperty = sProperties.getProperty("test-encrypted");
			assertTrue(StringUtils.equals(decryptedProperty, "TESTY"));
			
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testLoadSecurePropertiesFromInputStream(){
		try{
			File keyfile = temporaryFolder.newFile("test.key");
			
			assertTrue(keyfile.exists());
			KeyConfig2 config = new KeyConfig2(keyfile);
			KeystoreUtils2.generateSecretKey(config);
			KeysetHandle key = KeystoreUtils2.getSecretKey(keyfile);
			
			EncryptionProvider2 encryptionProvider = EncryptionProviderFactory2.getProvider(key);
			
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
			
			SecureProperties2 sProperties = new SecureProperties2(new FileInputStream(propertiesFile));
			assertNotNull(sProperties);
			String decryptedProperty = sProperties.getProperty("test-encrypted");
			assertTrue(StringUtils.equals(decryptedProperty, "TESTY"));
			
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testLoadSecurePropertiesFromInputStreamsAndParams(){
		try{
			File keyfile = temporaryFolder.newFile("test.key");
			
			assertTrue(keyfile.exists());
			KeyConfig2 config = new KeyConfig2(keyfile);
			KeystoreUtils2.generateSecretKey(config);
			KeysetHandle key = KeystoreUtils2.getSecretKey(keyfile);
			
			EncryptionProvider2 encryptionProvider = EncryptionProviderFactory2.getProvider(key);
			
			
			Properties clearProperties = new Properties();
			clearProperties.setProperty("test-encrypted", encryptionProvider.encrypt("TESTY"));
			
			File propertiesFile = temporaryFolder.newFile("test.properties");
			OutputStream stream = new FileOutputStream(propertiesFile);
			clearProperties.store(stream, "comment");
			stream.close();
			assertTrue(propertiesFile.exists());
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			FileReader reader = new FileReader(propertiesFile);
			SecureProperties2 sProperties = new SecureProperties2(new FileInputStream(propertiesFile),keyfile.getPath());
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
	public void testLoadSecurePropertiesFromFileAndParams(){
		try{
			File keyfile = temporaryFolder.newFile("test.key");
			
			assertTrue(keyfile.exists());
			KeyConfig2 config = new KeyConfig2(keyfile);
			KeystoreUtils2.generateSecretKey(config);
			KeysetHandle key = KeystoreUtils2.getSecretKey(keyfile);
			
			EncryptionProvider2 encryptionProvider = EncryptionProviderFactory2.getProvider(key);
			
			
			Properties clearProperties = new Properties();
			clearProperties.setProperty("test-encrypted", encryptionProvider.encrypt("TESTY"));
			
			File propertiesFile = temporaryFolder.newFile("test.properties");
			OutputStream stream = new FileOutputStream(propertiesFile);
			clearProperties.store(stream, "comment");
			stream.close();
			assertTrue(propertiesFile.exists());
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			FileReader reader = new FileReader(propertiesFile);
			SecureProperties2 sProperties = new SecureProperties2(propertiesFile,keyfile.getPath());
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
	public void testLoadSecurePropertiesFromInputStreamAndParams(){
		try{
			File keyfile = temporaryFolder.newFile("test.key");
			
			assertTrue(keyfile.exists());
			KeyConfig2 config = new KeyConfig2(keyfile);
			KeystoreUtils2.generateSecretKey(config);
			KeysetHandle key = KeystoreUtils2.getSecretKey(keyfile);
			
			EncryptionProvider2 encryptionProvider = EncryptionProviderFactory2.getProvider(key);
			
			
			Properties clearProperties = new Properties();
			clearProperties.setProperty("test-encrypted", encryptionProvider.encrypt("TESTY"));
			
			File propertiesFile = temporaryFolder.newFile("test.properties");
			OutputStream stream = new FileOutputStream(propertiesFile);
			clearProperties.store(stream, "comment");
			stream.close();
			assertTrue(propertiesFile.exists());
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			FileReader reader = new FileReader(propertiesFile);
			SecureProperties2 sProperties = new SecureProperties2(new FileInputStream(propertiesFile),keyfile.getPath());
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
	public void testLoadSecurePropertiesFromPathAndParams(){
		try{
			File keyfile = temporaryFolder.newFile("test.key");
			
			assertTrue(keyfile.exists());
			KeyConfig2 config = new KeyConfig2(keyfile);
			KeystoreUtils2.generateSecretKey(config);
			KeysetHandle key = KeystoreUtils2.getSecretKey(keyfile);
			
			EncryptionProvider2 encryptionProvider = EncryptionProviderFactory2.getProvider(key);
			
			
			Properties clearProperties = new Properties();
			clearProperties.setProperty("test-encrypted", encryptionProvider.encrypt("TESTY"));
			
			File propertiesFile = temporaryFolder.newFile("test.properties");
			OutputStream stream = new FileOutputStream(propertiesFile);
			clearProperties.store(stream, "comment");
			stream.close();
			assertTrue(propertiesFile.exists());
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			FileReader reader = new FileReader(propertiesFile);
			SecureProperties2 sProperties = new SecureProperties2(propertiesFile.getPath(),keyfile.getPath());
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
			KeyConfig2 config = new KeyConfig2(keyfile);
			KeystoreUtils2.generateSecretKey(config);
			
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
			SecureProperties2 sProperties = new SecureProperties2();
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
			KeyConfig2 config = new KeyConfig2(keyfile);
			KeystoreUtils2.generateSecretKey(config);
			
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
			SecureProperties2 sProperties = new SecureProperties2();
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
			KeyConfig2 config = new KeyConfig2(keyfile);
			KeystoreUtils2.generateSecretKey(config);
			
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			Properties props = new SecureProperties2();
			props.setProperty("entry-name", "aes-key");
			props.setProperty("keystore-password", "TEST");
			props.setProperty("key-path", keyfile.getPath());
			
			
			assertNotNull(((SecureProperties2)props).getKey());
			assertNotNull(((SecureProperties2)props).getEncryptionProvider());
			
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
			KeyConfig2 config = new KeyConfig2(keyfile);
			KeystoreUtils2.generateSecretKey(config);
			
		
			assertTrue(FileUtils.sizeOf(keyfile) > 0);
			
			Properties props = new SecureProperties2();
			props.setProperty("test", "test");
			
			assertTrue(StringUtils.equals("test", props.getProperty("test")));
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
}
