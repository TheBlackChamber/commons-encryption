package net.theblackchamber.crypto.constants;

import static org.junit.Assert.*;

import org.junit.Test;

public class SupportedKeyGenAlgorithmsTest {

	@Test
	public void testGetName() {

		assertTrue("AES".equals(SupportedKeyGenAlgorithms.AES.getName()));

	}

	public void testGetAlgorithm() {

		try {

			SupportedKeyGenAlgorithms alg = SupportedKeyGenAlgorithms.getAlgorithm("AES");

			assertNotNull(alg);
			assertTrue(SupportedKeyGenAlgorithms.AES == alg);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}

		try {

			SupportedKeyGenAlgorithms alg = SupportedKeyGenAlgorithms.getAlgorithm("DES");

			assertNotNull(alg);
			assertTrue(SupportedKeyGenAlgorithms.DES == alg);

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}

		try {

			SupportedKeyGenAlgorithms alg = SupportedKeyGenAlgorithms.getAlgorithm("ZES");

			fail();

		} catch (Exception e) {

		}

	}

}
