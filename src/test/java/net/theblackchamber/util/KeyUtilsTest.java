package net.theblackchamber.util;

import static org.junit.Assert.*;

import java.io.File;

import net.theblackchamber.key.SymetricSerializableKey;

import org.apache.commons.io.FileUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class KeyUtilsTest {

	@Rule
	public TemporaryFolder tempFolder = new TemporaryFolder();
	
	@Test
	public void testGenerateSymetricSerializableKey() {
		try {
			SymetricSerializableKey key = KeyUtils.generateSymetricSerializableKey();

			assertNotNull(key);
			assertNotNull(key.getSecretKey());

		} catch (Throwable t) {
			t.printStackTrace();
			fail();
		}
	}

	@Test
	public void testWriteSymetricSerializableKey(){
		
		try {
			SymetricSerializableKey key = KeyUtils.generateSymetricSerializableKey();

			assertNotNull(key);
			assertNotNull(key.getSecretKey());

			File file = tempFolder.newFile("private.key");
			assertTrue(file.exists());
			
			KeyUtils.writeSymetricSerializableKey(file, key);
			
			assertTrue(file.exists());
			assertTrue(FileUtils.sizeOf(file) > 0);
			
		} catch (Throwable t) {
			t.printStackTrace();
			fail();
		}
		
	}
	
}
