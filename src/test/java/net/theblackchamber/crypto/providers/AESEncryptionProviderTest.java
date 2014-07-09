package net.theblackchamber.crypto.providers;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.SecretKey;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import static org.junit.Assert.*;
import net.theblackchamber.crypto.util.KeystoreUtils;

public class AESEncryptionProviderTest {

	SecretKey key;
	AESEncryptionProvider aesEncryptionProvider;
	
	@Rule
	public TemporaryFolder tempFolder = new TemporaryFolder();
	
	@Before
	public void init(){
		try{
			File keyFile = tempFolder.newFile("keystore.keys");
			KeystoreUtils.generateAESSecretKey(keyFile);
			key = KeystoreUtils.getAESSecretKey(keyFile);
			aesEncryptionProvider = new AESEncryptionProvider(key);
		}catch(Exception e){
			e.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testEncrypt(){
		String clear = RandomStringUtils.randomAlphabetic(20);
		Set<String> crypts = new HashSet<String>();
		for(int i = 10;i<10;i++){
			String cipher = aesEncryptionProvider.encrypt(clear);
			assertTrue(!crypts.contains(cipher));
			crypts.add(cipher);
		}
		
	}
	
	@Test
	public void testDecrypt(){
		String clear = RandomStringUtils.randomAlphabetic(20);
		
		String cipher = aesEncryptionProvider.encrypt(clear);
		
		String decrypted = aesEncryptionProvider.decrypt(cipher);
		
		assertTrue(StringUtils.equals(clear, decrypted));
		
	}
	
}
