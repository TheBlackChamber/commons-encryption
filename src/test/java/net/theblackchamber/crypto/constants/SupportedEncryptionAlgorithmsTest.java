package net.theblackchamber.crypto.constants;

import static org.junit.Assert.*;

import org.junit.Test;

public class SupportedEncryptionAlgorithmsTest {

	@Test
	public void testGetName() {

		assertTrue("PBEWITHSHA256AND128BITAES-CBC-BC".equals(SupportedEncryptionAlgorithms.AES128.getAlgorithm()));
		assertTrue("PBEWITHSHA256AND192BITAES-CBC-BC".equals(SupportedEncryptionAlgorithms.AES192.getAlgorithm()));
		assertTrue("PBEWITHSHA256AND256BITAES-CBC-BC".equals(SupportedEncryptionAlgorithms.AES256.getAlgorithm()));
		assertTrue("PBEWithSHAAnd3KeyTripleDES".equals(SupportedEncryptionAlgorithms.DES.getAlgorithm()));
		
	}

}
