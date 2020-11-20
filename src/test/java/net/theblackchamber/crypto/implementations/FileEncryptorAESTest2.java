package net.theblackchamber.crypto.implementations;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileOutputStream;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.google.crypto.tink.KeysetHandle;

import net.theblackchamber.crypto.model.KeyConfig2;
import net.theblackchamber.crypto.providers.EncryptionProvider2;
import net.theblackchamber.crypto.providers.EncryptionProviderFactory2;
import net.theblackchamber.crypto.util.KeystoreUtils2;

public class FileEncryptorAESTest2 {

	@Rule
	public TemporaryFolder temporaryFolder = new TemporaryFolder();

	private FileEncryptor2 fileEncryptor;

	@Before
	public void init() {
		try {
			File keyFile = temporaryFolder.newFile("keystore.keys");

			KeyConfig2 config = new KeyConfig2(keyFile,"test");
			KeystoreUtils2.generateSecretKey(config);

			KeysetHandle key256 = KeystoreUtils2.getSecretKey(config);

			assertNotNull(key256);

			EncryptionProvider2 provider = EncryptionProviderFactory2.getProvider(key256);

			fileEncryptor = new FileEncryptor2(provider);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	@Test
	public void testFileEncryptRetailOriginal() {

		try {

			File testClearFile = temporaryFolder.newFile("test.fil");

			assertTrue(testClearFile.exists());

			FileOutputStream fos = new FileOutputStream(testClearFile);
			IOUtils.write("this is a test".getBytes(), fos);

			fos.close();

			fileEncryptor.encryptFile(testClearFile, false);

			assertTrue(testClearFile.exists());

			File encrypted = FileUtils.getFile(testClearFile.getAbsolutePath() + ".encrypted");

			assertTrue(encrypted.exists());

			String contents = FileUtils.readFileToString(new File(testClearFile.getAbsolutePath() + ".encrypted"));

			assertFalse("this is a test".equals(contents));

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}

	}

	@Test
	public void testFileEncryptReplaceOriginal() {

		try {

			File testClearFile = temporaryFolder.newFile("test.fil");

			assertTrue(testClearFile.exists());

			FileOutputStream fos = new FileOutputStream(testClearFile);
			IOUtils.write("this is a test".getBytes(), fos);

			fos.close();

			fileEncryptor.encryptFile(testClearFile);

			assertTrue(testClearFile.exists());

			File encrypted = FileUtils.getFile(testClearFile.getAbsolutePath() + ".encrypted");

			assertFalse(encrypted.exists());

			String contents = FileUtils.readFileToString(new File(testClearFile.getAbsolutePath()));

			assertFalse("this is a test".equals(contents));

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}

	}

}
