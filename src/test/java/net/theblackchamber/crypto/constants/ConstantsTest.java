package net.theblackchamber.crypto.constants;

import static org.junit.Assert.*;

import org.junit.Test;

public class ConstantsTest {

	@Test
	public void testConstants() {

		assertTrue(Constants.ENTRY_NAME_PROPERTY_KEY.equals("entry-name"));
		assertTrue(Constants.KEY_PATH_PROPERTY_KEY.equals("key-path"));
		assertTrue(Constants.KEYSTORE_PASSWORD_PROPERTY_KEY.equals("keystore-password"));

	}

}
