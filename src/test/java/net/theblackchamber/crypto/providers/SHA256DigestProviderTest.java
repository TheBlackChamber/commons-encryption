package net.theblackchamber.crypto.providers;

import net.theblackchamber.crypto.providers.digest.SHA256DigestProvider;

import static org.junit.Assert.*;
import org.junit.Test;

public class SHA256DigestProviderTest {

	@Test
	public void testDigest(){
		
		SHA256DigestProvider provider = new SHA256DigestProvider();
		String prevHash = null;
		String clear = "test";
		
		for(int i = 0 ; i <10 ; i++){
			
			String hashed = provider.digest(clear);
			
			assertFalse(clear.equals(hashed));
			
			if(prevHash == null){
				prevHash = hashed;
			}else{
				assertTrue(prevHash.equals(hashed));
				prevHash = hashed;
			}
			
		}
		
	}
	

}
