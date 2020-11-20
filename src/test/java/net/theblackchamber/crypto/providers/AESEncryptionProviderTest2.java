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
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.SecretKey;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.google.crypto.tink.KeysetHandle;

import static org.junit.Assert.*;
import net.theblackchamber.crypto.constants.SupportedKeyGenAlgorithms;
import net.theblackchamber.crypto.exceptions.MissingParameterException;
import net.theblackchamber.crypto.exceptions.UnsupportedAlgorithmException;
import net.theblackchamber.crypto.exceptions.UnsupportedKeySizeException;
import net.theblackchamber.crypto.model.KeyConfig;
import net.theblackchamber.crypto.model.KeyConfig2;
import net.theblackchamber.crypto.providers.symmetric.AESEncryptionProvider;
import net.theblackchamber.crypto.providers.symmetric.AESEncryptionProvider2;
import net.theblackchamber.crypto.util.KeystoreUtils;
import net.theblackchamber.crypto.util.KeystoreUtils2;

public class AESEncryptionProviderTest2 {

	KeysetHandle			key;

	@Rule
	public TemporaryFolder	tempFolder	= new TemporaryFolder();

	@Before
	public void init() {
		try {
			File keyFile = tempFolder.newFile("keystore.keys");

			KeyConfig2 config = new KeyConfig2(keyFile, "test");
			KeystoreUtils2.generateSecretKey(config);

			key = KeystoreUtils2.getSecretKey(config);

			assertNotNull(key);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testEncryptBytesAssociated() throws GeneralSecurityException, MissingParameterException {

		EncryptionProvider2 aesEncryptionProvider = EncryptionProviderFactory2.getProvider(key);

		assertNotNull(aesEncryptionProvider.getKey());

		byte[] clear = RandomStringUtils.randomAlphabetic(20).getBytes();
		byte[] assoc = RandomStringUtils.randomAlphabetic(20).getBytes();

		for (int i = 1; i < 10; i++) {

			byte[] cipher = aesEncryptionProvider.encrypt(clear,assoc);
			byte[] badCipher = aesEncryptionProvider.encrypt(clear);

			assertFalse(Arrays.equals(cipher, badCipher));
			assertFalse(Arrays.equals(cipher, clear));

		}

		try {
			aesEncryptionProvider.encrypt("".getBytes());
			fail();
		} catch (MissingParameterException mpe) {
			// Expected behavior
		}

	}
	
	@Test
	public void testEncryptBytes() throws GeneralSecurityException, MissingParameterException {

		EncryptionProvider2 aesEncryptionProvider = EncryptionProviderFactory2.getProvider(key);

		assertNotNull(aesEncryptionProvider.getKey());

		String clear = RandomStringUtils.randomAlphabetic(20);

		for (int i = 1; i < 10; i++) {

			byte[] cipher = aesEncryptionProvider.encrypt(clear.getBytes());

			assertFalse(Arrays.equals(cipher, clear.getBytes()));

		}

		try {
			aesEncryptionProvider.encrypt("".getBytes());
			fail();
		} catch (MissingParameterException mpe) {
			// Expected behavior
		}

	}

	@Test
	public void testEncrypt() {

		try {

			EncryptionProvider2 aesEncryptionProvider = EncryptionProviderFactory2.getProvider(key);

			assertNotNull(aesEncryptionProvider.getKey());

			String clear = RandomStringUtils.randomAlphabetic(20);
			Set<String> crypts = new HashSet<String>();
			for (int i = 1; i < 10; i++) {
				String cipher = new String(aesEncryptionProvider.encrypt(clear));
				assertTrue(!crypts.contains(cipher));
				crypts.add(cipher);
			}

			try {
				aesEncryptionProvider.encrypt("");
				fail();
			} catch (MissingParameterException mpe) {

			}

		} catch (Throwable t) {
			t.printStackTrace();
			fail();
		}
	}

	@Test
	public void testEncryptMultProviders() {

		try {

			EncryptionProvider2 aesEncryptionProvider = EncryptionProviderFactory2.getProvider(key);
			EncryptionProvider2 aesEncryptionProvider2 = EncryptionProviderFactory2.getProvider(key);

			assertNotNull(aesEncryptionProvider.getKey());

			String clear = RandomStringUtils.randomAlphabetic(20);
			Set<String> crypts = new HashSet<String>();
			for (int i = 1; i < 10; i++) {
				String cipher = new String(aesEncryptionProvider.encrypt(clear));
				assertTrue(!crypts.contains(cipher));
				crypts.add(cipher);
				cipher = new String(aesEncryptionProvider2.encrypt(clear));
				assertTrue(!crypts.contains(cipher));
				crypts.add(cipher);
			}

			try {
				aesEncryptionProvider.encrypt("");
				fail();
			} catch (MissingParameterException mpe) {

			}

		} catch (Throwable t) {
			t.printStackTrace();
			fail();
		}
	}

	@Test
	public void testDecryptBytes() throws GeneralSecurityException, MissingParameterException {

		
		EncryptionProvider2 aesEncryptionProvider = EncryptionProviderFactory2.getProvider(key);

		assertNotNull(aesEncryptionProvider.getKey());

		byte[] clear = RandomStringUtils.randomAlphabetic(20).getBytes();

		byte[] cipher = aesEncryptionProvider.encrypt(clear);

		byte[] decrypted = aesEncryptionProvider.decrypt(cipher);

		assertTrue(Arrays.equals(clear, decrypted));

		try {
			aesEncryptionProvider.decrypt("".getBytes());
			fail();
		} catch (MissingParameterException mpe) {
			//expected behavior
		}

	}

	@Test
	public void testDecryptBytesAssociated() throws GeneralSecurityException, MissingParameterException {

		
		EncryptionProvider2 aesEncryptionProvider = EncryptionProviderFactory2.getProvider(key);

		assertNotNull(aesEncryptionProvider.getKey());

		byte[] clear = RandomStringUtils.randomAlphabetic(20).getBytes();
		byte[] associated = RandomStringUtils.randomAlphabetic(20).getBytes();

		byte[] cipher = aesEncryptionProvider.encrypt(clear,associated);

		byte[] decrypted = aesEncryptionProvider.decrypt(cipher,associated);

		assertTrue(Arrays.equals(clear, decrypted));

		try {
			aesEncryptionProvider.decrypt("".getBytes());
			fail();
		} catch (MissingParameterException mpe) {
			//expected behavior
		}

	}
	
	@Test
	public void testDecrypt() {
		try {
			
			EncryptionProvider2 aesEncryptionProvider = EncryptionProviderFactory2.getProvider(key);

			assertNotNull(aesEncryptionProvider.getKey());

			String clear = RandomStringUtils.randomAlphabetic(20);

			String cipher = new String(aesEncryptionProvider.encrypt(clear));

			String decrypted = new String(aesEncryptionProvider.decrypt(cipher));

			assertTrue(StringUtils.equals(clear, decrypted));

			try {
				aesEncryptionProvider.decrypt("");
				fail();
			} catch (MissingParameterException mpe) {

			}

		} catch (Throwable t) {
			t.printStackTrace();
			fail();
		}
	}

}
