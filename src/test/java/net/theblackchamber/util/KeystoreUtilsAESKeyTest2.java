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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStoreException;

import javax.crypto.SecretKey;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.google.crypto.tink.KeysetHandle;

import net.theblackchamber.crypto.constants.SupportedKeyGenAlgorithms;
import net.theblackchamber.crypto.model.KeyConfig;
import net.theblackchamber.crypto.model.KeyConfig2;
import net.theblackchamber.crypto.util.KeystoreUtils;
import net.theblackchamber.crypto.util.KeystoreUtils2;

public class KeystoreUtilsAESKeyTest2 {

	@Rule
	public TemporaryFolder temporaryFolder = new TemporaryFolder();
	
	@Test
	public void testgenerateSecretKey(){
		
		try {
			File file = temporaryFolder.newFile("test.key");
			KeyConfig2 config = new KeyConfig2(file);
			KeystoreUtils2.generateSecretKey(config);
			
			assertTrue(FileUtils.sizeOf(file) > 0);
			
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
		
	}
	
	@Test
	public void testgenerateSecretKeyNullKeystore(){
		
		try {
			
			KeystoreUtils2.generateSecretKey(null);
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
	public void testgenerateSecretKeyWhenExists(){
		
		try {
			File file = temporaryFolder.newFile("test.key");
			KeyConfig2 config = new KeyConfig2(file);
			KeystoreUtils2.generateSecretKey(config);
			long fileSize = FileUtils.sizeOf(file);
			assertTrue(fileSize > 0);
			String contents = FileUtils.readFileToString(file);
			KeyConfig2 config2 = new KeyConfig2(file);
			KeystoreUtils2.generateSecretKey(config2);
			String contents2 = FileUtils.readFileToString(file);
			assertTrue(!StringUtils.equals(contents, contents2));
			
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
		
	}
	
	
	@Test
	public void testLoadAESSecretKey(){
		try {
			File file = temporaryFolder.newFile("test.key");
			KeyConfig2 config = new KeyConfig2(file);
			KeystoreUtils2.generateSecretKey(config);
			
			assertTrue(FileUtils.sizeOf(file) > 0);
			
			KeysetHandle key = KeystoreUtils2.getSecretKey(file);
			
			assertNotNull(key);
			
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
}
