package net.theblackchamber.util;

import net.theblackchamber.key.SymetricSerializableKey;

public class Tester {

	public static void main(String[] args) {
		SymetricSerializableKey key = KeyUtils.generateSymetricSerializableKey();
		System.out.println(key.getSecretKey());
	}

}
