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
import net.theblackchamber.crypto.constants.SupportedAlgorithms;
import net.theblackchamber.crypto.model.KeyConfig;
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
			
			KeyConfig config = new KeyConfig(keyFile, "TEST", null, SupportedAlgorithms.AES, "aes-key");
			
			KeystoreUtils.generateAESSecretKey(config);
			key = KeystoreUtils.getAESSecretKey(keyFile,"aes-key","TEST");
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
