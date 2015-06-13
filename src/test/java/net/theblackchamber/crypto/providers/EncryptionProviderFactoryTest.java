package net.theblackchamber.crypto.providers;

import java.io.File;

import javax.crypto.SecretKey;

import net.theblackchamber.crypto.constants.SupportedKeyGenAlgorithms;
import net.theblackchamber.crypto.model.KeyConfig;
import net.theblackchamber.crypto.util.KeystoreUtils;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import static org.junit.Assert.*;

public class EncryptionProviderFactoryTest {

	SecretKey aesKey256;
	SecretKey aesKey192;
	SecretKey aesKey128;
	SecretKey desKey128;
	SecretKey desKey192;
	
	@Rule
	public TemporaryFolder tempFolder = new TemporaryFolder();
	
	@Before
	public void init() {
		try {
			File keyFile = tempFolder.newFile("keystore.keys");

			KeyConfig config = new KeyConfig(keyFile, "TEST", 256,
					SupportedKeyGenAlgorithms.AES, "aes-key-256");
			KeystoreUtils.generateSecretKey(config);
			
			config = new KeyConfig(keyFile, "TEST", 192,
					SupportedKeyGenAlgorithms.AES, "aes-key-192");
			KeystoreUtils.generateSecretKey(config);
			
			config = new KeyConfig(keyFile, "TEST", 128,
					SupportedKeyGenAlgorithms.AES, "aes-key-128");
			KeystoreUtils.generateSecretKey(config);
			
			config = new KeyConfig(keyFile, "TEST", 128,
					SupportedKeyGenAlgorithms.DESede, "des-key-128");
			KeystoreUtils.generateSecretKey(config);
			
			config = new KeyConfig(keyFile, "TEST", 192,
					SupportedKeyGenAlgorithms.DESede, "des-key-192");
			KeystoreUtils.generateSecretKey(config);
			

			aesKey256 = KeystoreUtils.getSecretKey(keyFile, "aes-key-256", "TEST");
			aesKey192 = KeystoreUtils.getSecretKey(keyFile, "aes-key-192", "TEST");
			aesKey128 = KeystoreUtils.getSecretKey(keyFile, "aes-key-128", "TEST");
			desKey192 = KeystoreUtils.getSecretKey(keyFile, "des-key-192", "TEST");
			desKey128 = KeystoreUtils.getSecretKey(keyFile, "des-key-128", "TEST");

			assertNotNull(aesKey256);
			assertNotNull(aesKey192);
			assertNotNull(aesKey128);
			assertNotNull(desKey192);
			assertNotNull(desKey128);
			

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testGetProviderAES(){
		
		try{
		
			EncryptionProvider encryptionProvider = EncryptionProviderFactory.getProvider(aesKey256);
			assertNotNull(encryptionProvider);
			assertTrue(encryptionProvider.getKey().getAlgorithm().equals("AES"));
			assertTrue(encryptionProvider.getKey().getEncoded().length == 32);
			
			encryptionProvider = EncryptionProviderFactory.getProvider(aesKey192);
			assertNotNull(encryptionProvider);
			assertTrue(encryptionProvider.getKey().getAlgorithm().equals("AES"));
			assertTrue(encryptionProvider.getKey().getEncoded().length == 24);
			
			encryptionProvider = EncryptionProviderFactory.getProvider(aesKey128);
			assertNotNull(encryptionProvider);
			assertTrue(encryptionProvider.getKey().getAlgorithm().equals("AES"));
			assertTrue(encryptionProvider.getKey().getEncoded().length == 16);
			
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}

	@Test
	public void testGetProviderDES(){
		
		try{
		
//			EncryptionProvider<SecretKey> encryptionProvider = EncryptionProviderFactory.getProvider(aesKey256);
//			assertNotNull(encryptionProvider);
//			assertTrue(encryptionProvider.getKey().getAlgorithm().equals("DESede"));
//			assertTrue(encryptionProvider.getKey().getEncoded().length == 32);
			
			EncryptionProvider encryptionProvider = EncryptionProviderFactory.getProvider(desKey192);
			assertNotNull(encryptionProvider);
			assertTrue(encryptionProvider.getKey().getAlgorithm().equals("DESede"));
			assertTrue(encryptionProvider.getKey().getEncoded().length == 24);
			
			encryptionProvider = EncryptionProviderFactory.getProvider(desKey128);
			assertNotNull(encryptionProvider);
			assertTrue(encryptionProvider.getKey().getAlgorithm().equals("DESede"));
			assertTrue(encryptionProvider.getKey().getEncoded().length == 16);
			
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
}
