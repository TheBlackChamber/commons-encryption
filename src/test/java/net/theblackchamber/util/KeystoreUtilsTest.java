package net.theblackchamber.util;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

import javax.crypto.SecretKey;

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
	public void testGenerateAESSecretKey(){
		
		try {
			File file = temporaryFolder.newFile("test.key");
			
			KeystoreUtils.generateAESSecretKey(file);
			
			assertTrue(FileUtils.sizeOf(file) > 0);
			
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
		
	}
	
	@Test
	public void testGenerateAESSecretKeyNullKeystore(){
		
		try {
			
			KeystoreUtils.generateAESSecretKey(null);
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
	public void testGenerateAESSecretKeyNoEntryName(){
		
		try {
			
			File file = temporaryFolder.newFile("test.key");
			
			KeystoreUtils.generateAESSecretKey(file,null);
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
	public void testGenerateAESSecretKeyCustomEntryName(){
		
		try {
			File file = temporaryFolder.newFile("test.key");
			
			KeystoreUtils.generateAESSecretKey(file,"aes-key");
			
			assertTrue(FileUtils.sizeOf(file) > 0);
			
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
		
	}
	
	
	@Test
	public void testGenerateAESSecretKeyWhenExists(){
		
		try {
			File file = temporaryFolder.newFile("test.key");
			
			KeystoreUtils.generateAESSecretKey(file);
			long fileSize = FileUtils.sizeOf(file);
			assertTrue(fileSize > 0);
			
			KeystoreUtils.generateAESSecretKey(file,"aes-key2");
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
			
			KeystoreUtils.generateAESSecretKey(file);
			
			assertTrue(FileUtils.sizeOf(file) > 0);
			
			SecretKey key = KeystoreUtils.getAESSecretKey(file);
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
	public void testLoadAESSecretKeyNullKeystore(){
		try {
			
			SecretKey key = KeystoreUtils.getAESSecretKey(null);
			
			fail();
			
		} catch(FileNotFoundException fnf){
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
			
			KeystoreUtils.generateAESSecretKey(file,"aes-key");
			
			assertTrue(FileUtils.sizeOf(file) > 0);
			
			SecretKey key = KeystoreUtils.getAESSecretKey(file);
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
