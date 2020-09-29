package net.theblackchamber.crypto.providers;

import java.io.File;

import javax.crypto.SecretKey;

import net.theblackchamber.crypto.constants.SupportedKeyGenAlgorithms;
import net.theblackchamber.crypto.model.KeyConfig;
import net.theblackchamber.crypto.model.KeyConfig2;
import net.theblackchamber.crypto.util.KeystoreUtils;
import net.theblackchamber.crypto.util.KeystoreUtils2;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.google.crypto.tink.KeysetHandle;

import static org.junit.Assert.*;

public class EncryptionProviderFactoryTest2 {

	KeysetHandle aesKey;
	
	
	@Rule
	public TemporaryFolder tempFolder = new TemporaryFolder();
	
	@Before
	public void init() {
		try {
			File keyFile = tempFolder.newFile("keystore.keys");

			KeyConfig2 config = new KeyConfig2(keyFile);
			KeystoreUtils2.generateSecretKey(config);
			

			aesKey = KeystoreUtils2.getSecretKey(keyFile);
			

			assertNotNull(aesKey);
			

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testGetProviderAES(){
		
		try{
		
			EncryptionProvider2 encryptionProvider = EncryptionProviderFactory2.getProvider(aesKey);
			assertNotNull(encryptionProvider);
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
}
