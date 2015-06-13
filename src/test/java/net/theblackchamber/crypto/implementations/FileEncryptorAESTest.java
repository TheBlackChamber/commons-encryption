package net.theblackchamber.crypto.implementations;

import static org.junit.Assert.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;

import javax.crypto.SecretKey;

import net.theblackchamber.crypto.constants.SupportedKeyGenAlgorithms;
import net.theblackchamber.crypto.model.KeyConfig;
import net.theblackchamber.crypto.providers.AESEncryptionProvider;
import net.theblackchamber.crypto.providers.EncryptionProvider;
import net.theblackchamber.crypto.providers.EncryptionProviderFactory;
import net.theblackchamber.crypto.util.KeystoreUtils;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class FileEncryptorAESTest {

	@Rule
	public TemporaryFolder temporaryFolder = new TemporaryFolder();

	private FileEncryptor fileEncryptor;

	@Before
	public void init() {
		try {
			File keyFile = temporaryFolder.newFile("keystore.keys");

			KeyConfig config = new KeyConfig(keyFile, "TEST", 256,
					SupportedKeyGenAlgorithms.AES, "aes-key-256");
			KeystoreUtils.generateSecretKey(config);

			SecretKey key256 = KeystoreUtils.getSecretKey(keyFile, "aes-key-256", "TEST");

			assertNotNull(key256);

			EncryptionProvider provider = EncryptionProviderFactory.getProvider(key256);

			fileEncryptor = new FileEncryptor(provider);

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

	// @Before
	// public void init(){
	//
	// File tempFile = FileUtils.getFile(temporaryFolder.getRoot() +
	// File.separator + "test.fil");
	//
	// }

}
