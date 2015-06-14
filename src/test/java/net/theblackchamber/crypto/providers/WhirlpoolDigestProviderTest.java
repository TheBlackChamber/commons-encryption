package net.theblackchamber.crypto.providers;

import java.util.HashSet;
import java.util.Set;

import net.theblackchamber.crypto.providers.digest.SHA256DigestProvider;
import net.theblackchamber.crypto.providers.digest.WhirlpoolDigestProvider;
import static org.junit.Assert.*;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Test;

public class WhirlpoolDigestProviderTest {

	@Test
	public void testDigest(){
		
		WhirlpoolDigestProvider provider = new WhirlpoolDigestProvider();
		String prevHash = null;
		String clear = "test";
		
		for(int i = 0 ; i <10 ; i++){
			
			String hashed = provider.digest(clear);
			
			assertFalse(clear.equals(hashed));
			assertTrue(hashed.length() == 128);
			
			if(prevHash == null){
				prevHash = hashed;
			}else{
				assertTrue(prevHash.equals(hashed));
				prevHash = hashed;
			}
			
		}
		
		Set<String> hashes = new HashSet<String>();
		Set<String> clears = new HashSet<String>();
		for(int i = 0 ; i <1000;i++){
			
			String clearString = RandomStringUtils.randomAlphanumeric(50);
			
			while(clears.contains(clearString)){
				clearString = RandomStringUtils.randomAlphanumeric(50);
			}
			
			String hashed = provider.digest(clearString);
			
			assertFalse(hashes.contains(hashed));
			
			hashes.add(hashed);
			
		}
		
	}
	

}
