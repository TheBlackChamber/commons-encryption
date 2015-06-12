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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStoreException;

import javax.crypto.SecretKey;

import junit.framework.Assert;
import net.theblackchamber.crypto.constants.SupportedKeyGenAlgorithms;
import net.theblackchamber.crypto.model.KeyConfig;
import net.theblackchamber.crypto.util.KeystoreUtils;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Rule;
import org.junit.Test;

import static org.junit.Assert.*;

import org.junit.rules.TemporaryFolder;

public class KeystoreUtilsTest {

	@Rule
	public TemporaryFolder temporaryFolder = new TemporaryFolder();
	
	@Test
	public void testgenerateSecretKey(){
		
		try {
			File file = temporaryFolder.newFile("test.key");
			KeyConfig config = new KeyConfig(file, "TEST", null, SupportedKeyGenAlgorithms.AES, "aes-key");
			KeystoreUtils.generateSecretKey(config);
			
			assertTrue(FileUtils.sizeOf(file) > 0);
			
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
		
	}
	
	@Test
	public void testgenerateSecretKey128(){
		
		try {
			File file = temporaryFolder.newFile("test.key");
			KeyConfig config = new KeyConfig(file, "TEST", 128, SupportedKeyGenAlgorithms.AES, "aes-key");
			KeystoreUtils.generateSecretKey(config);
			
			assertTrue(FileUtils.sizeOf(file) > 0);
			
			SecretKey key = KeystoreUtils.getSecretKey(file, "aes-key", "TEST");
			
			byte[] bytes = key.getEncoded();
			
			assertTrue(bytes.length == 16);
			
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
		
	}
	
	@Test
	public void testgenerateSecretKey192(){
		
		try {
			File file = temporaryFolder.newFile("test.key");
			KeyConfig config = new KeyConfig(file, "TEST", 192, SupportedKeyGenAlgorithms.AES, "aes-key");
			KeystoreUtils.generateSecretKey(config);
			
			assertTrue(FileUtils.sizeOf(file) > 0);
			
			SecretKey key = KeystoreUtils.getSecretKey(file, "aes-key", "TEST");
			
			byte[] bytes = key.getEncoded();
			
			assertTrue(bytes.length == 24);
			
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
		
	}
	
	@Test
	public void testgenerateSecretKey256(){
		
		try {
			File file = temporaryFolder.newFile("test.key");
			KeyConfig config = new KeyConfig(file, "TEST", 256, SupportedKeyGenAlgorithms.AES, "aes-key");
			KeystoreUtils.generateSecretKey(config);
			
			assertTrue(FileUtils.sizeOf(file) > 0);
			
			SecretKey key = KeystoreUtils.getSecretKey(file, "aes-key", "TEST");
			
			byte[] bytes = key.getEncoded();
			
			assertTrue(bytes.length == 32);
			
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
		
	}
	
	@Test
	public void testgenerateSecretKeyNullKeystore(){
		
		try {
			
			KeystoreUtils.generateSecretKey(null);
			fail();
			
		} catch (Exception e) {
			
			if(StringUtils.equals("Missing parameters, unable to create keystore.", e.getMessage())){
				assertTrue(true);
			}else{
				e.printStackTrace();
				fail();
			}
		}
		
	}
	
	@Test
	public void testgenerateSecretKeyNoEntryName(){
		
		try {
			
			File file = temporaryFolder.newFile("test.key");
			KeyConfig config = new KeyConfig(file, "TEST", null, SupportedKeyGenAlgorithms.AES, null);
			KeystoreUtils.generateSecretKey(config);
			fail();
			
		} catch (Exception e) {
			
			if(StringUtils.equals("Missing parameters, unable to create keystore.", e.getMessage())){
				assertTrue(true);
			}else{
				e.printStackTrace();
				fail();
			}
		}
		
	}
	
	@Test
	public void testgenerateSecretKeyCustomEntryName(){
		
		try {
			File file = temporaryFolder.newFile("test.key");
			KeyConfig config = new KeyConfig(file, "TEST", null, SupportedKeyGenAlgorithms.AES, "aes-key");
			KeystoreUtils.generateSecretKey(config);
			
			assertTrue(FileUtils.sizeOf(file) > 0);
			
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
		
	}
	
	
	@Test
	public void testgenerateSecretKeyWhenExists(){
		
		try {
			File file = temporaryFolder.newFile("test.key");
			KeyConfig config = new KeyConfig(file, "TEST", null, SupportedKeyGenAlgorithms.AES, "aes-key");
			KeystoreUtils.generateSecretKey(config);
			long fileSize = FileUtils.sizeOf(file);
			assertTrue(fileSize > 0);
			KeyConfig config2 = new KeyConfig(file, "TEST", null, SupportedKeyGenAlgorithms.AES, "aes-key2");
			KeystoreUtils.generateSecretKey(config2);
			assertTrue(FileUtils.sizeOf(file) > 0);
			assertTrue(FileUtils.sizeOf(file) > fileSize);
			
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
		
	}
	
	
	@Test
	public void testLoadAESSecretKey(){
		try {
			File file = temporaryFolder.newFile("test.key");
			KeyConfig config = new KeyConfig(file, "TEST", null, SupportedKeyGenAlgorithms.AES, "aes-key");
			KeystoreUtils.generateSecretKey(config);
			
			assertTrue(FileUtils.sizeOf(file) > 0);
			
			SecretKey key = KeystoreUtils.getSecretKey(file,config.getKeyEntryName(),config.getKeyStorePassword());
			byte[] bytes = key.getEncoded();
			String str = Hex.toHexString(bytes);
			
			assertNotNull(key);
			assertNotNull(str);
			
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
		
	@Test
	public void testLoadAESSecretKeyNullPassword(){
		try {
			File file = temporaryFolder.newFile("test.key");
			KeyConfig config = new KeyConfig(file, "TEST", null, SupportedKeyGenAlgorithms.AES, "aes-key");
			KeystoreUtils.generateSecretKey(config);
			SecretKey key = KeystoreUtils.getSecretKey(file,"aes-key",null);
			
			fail();
			
		} catch(KeyStoreException fnf){
			assertTrue(true);
		}catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testLoadAESSecretKeyInputStreamNullPassword(){
		try {
			File file = temporaryFolder.newFile("test.key");
			KeyConfig config = new KeyConfig(file, "TEST", null, SupportedKeyGenAlgorithms.AES, "aes-key");
			KeystoreUtils.generateSecretKey(config);
			SecretKey key = KeystoreUtils.getSecretKey(new FileInputStream(file),"aes-key",null);
			
			fail();
			
		} catch(KeyStoreException fnf){
			assertTrue(true);
		}catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testLoadAESSecretKeyNullKeyEntry(){
		try {
			File file = temporaryFolder.newFile("test.key");
			KeyConfig config = new KeyConfig(file, "TEST", null, SupportedKeyGenAlgorithms.AES, "aes-key");
			KeystoreUtils.generateSecretKey(config);
			SecretKey key = KeystoreUtils.getSecretKey(file,null,"TEST");
			
			fail();
			
		} catch(KeyStoreException fnf){
			assertTrue(true);
		}catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testLoadAESSecretKeyInputStreamNullKeyEntry(){
		try {
			File file = temporaryFolder.newFile("test.key");
			KeyConfig config = new KeyConfig(file, "TEST", null, SupportedKeyGenAlgorithms.AES, "aes-key");
			KeystoreUtils.generateSecretKey(config);
			SecretKey key = KeystoreUtils.getSecretKey(new FileInputStream(file),null,"TEST");
			
			fail();
			
		} catch(KeyStoreException fnf){
			assertTrue(true);
		}catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testLoadAESSecretKeyCustomEntryName(){
		try {
			File file = temporaryFolder.newFile("test.key");
			KeyConfig config = new KeyConfig(file, "TEST", null, SupportedKeyGenAlgorithms.AES, "aes-key");
			KeystoreUtils.generateSecretKey(config);
			
			assertTrue(FileUtils.sizeOf(file) > 0);
			
			SecretKey key = KeystoreUtils.getSecretKey(file,config.getKeyEntryName(),config.getKeyStorePassword());
			byte[] bytes = key.getEncoded();
			String str = Hex.toHexString(bytes);
			
			assertNotNull(key);
			assertNotNull(str);
			
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
}
