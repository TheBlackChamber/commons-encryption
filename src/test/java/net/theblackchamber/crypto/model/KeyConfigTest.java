package net.theblackchamber.crypto.model;

import static org.junit.Assert.*;

import java.io.File;

import net.theblackchamber.crypto.constants.SupportedAlgorithms;

import org.apache.commons.lang3.StringUtils;
import org.junit.Test;

public class KeyConfigTest {

	@Test
	public void testFullConstructor(){
		try{
			
			KeyConfig config = new KeyConfig(new File("/tmp/test"), "TEST", 256, SupportedAlgorithms.AES, "TEST");
			
			assertNotNull(config);
			
			assertNotNull(config.getKeyStoreFile());
			assertNotNull(config.getKeySize());
			config.setKeySize(null);
			assertNotNull(config.getKeySize());
			assertTrue(config.getAlgorithm() != null);
			assertTrue(!StringUtils.isEmpty(config.getKeyEntryName()));
			assertTrue(!StringUtils.isEmpty(config.getKeyStorePassword()));
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testEmptyConstructor(){
		try{
			
			KeyConfig config = new KeyConfig();
			
			assertNotNull(config);
			
			config.setAlgorithm(SupportedAlgorithms.AES);
			config.setKeyStoreFile(new File("/tmp/test"));
			config.setKeyEntryName("TEST");
			config.setKeySize(256);
			config.setKeyStorePassword("TEST");
			
			assertNotNull(config.getKeyStoreFile());
			assertNotNull(config.getKeySize());
			config.setKeySize(null);
			assertNotNull(config.getKeySize());
			assertTrue(config.getAlgorithm() != null);
			assertTrue(!StringUtils.isEmpty(config.getKeyEntryName()));
			assertTrue(!StringUtils.isEmpty(config.getKeyStorePassword()));
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
}
