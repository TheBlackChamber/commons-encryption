package net.theblackchamber.crypto.providers;

import java.util.HashSet;
import java.util.Set;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;
import net.theblackchamber.crypto.key.SymetricSerializableKey;
import net.theblackchamber.crypto.util.KeyUtils;

public class AESEncryptionProviderTest {

	SymetricSerializableKey key;
	AESEncryptionProvider aesEncryptionProvider;
	
	@Before
	public void init(){
		key = KeyUtils.generateSymetricSerializableKey();
		aesEncryptionProvider = new AESEncryptionProvider(key);
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
