package net.theblackchamber.crypto.providers;

import net.theblackchamber.crypto.providers.digest.SHA256DigestProvider;
import net.theblackchamber.crypto.providers.digest.WhirlpoolDigestProvider;
import static org.junit.Assert.*;

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
		
	}
	

}
