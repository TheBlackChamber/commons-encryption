package net.theblackchamber.util;

import java.io.File;
import java.io.IOException;

import javax.crypto.SecretKey;

import net.theblackchamber.crypto.util.KeystoreUtils;

import org.apache.commons.io.FileUtils;
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
	
}
