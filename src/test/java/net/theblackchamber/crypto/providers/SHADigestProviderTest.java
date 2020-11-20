package net.theblackchamber.crypto.providers;

import java.util.HashSet;
import java.util.Set;

import net.theblackchamber.crypto.providers.digest.SHA256DigestProvider;
import net.theblackchamber.crypto.providers.digest.SHA256DigestProvider.TYPE;

import static org.junit.Assert.*;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Test;

public class SHADigestProviderTest {

	@Test
	public void testDigest256(){
		
		SHA256DigestProvider provider = new SHA256DigestProvider(TYPE.SHA256);
		String prevHash = null;
		String clear = "test";
		
		for(int i = 0 ; i <10 ; i++){
			
			String hashed = provider.digest(clear);
			
			assertFalse(clear.equals(hashed));
			assertTrue(hashed.length() == 64);
			
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
			assertTrue(hashed.length() == 64);
			assertFalse(hashes.contains(hashed));
			
			hashes.add(hashed);
			
		}
		
	}
	
	@Test
	public void testDigest1(){
		
		SHA256DigestProvider provider = new SHA256DigestProvider(TYPE.SHA1);
		String prevHash = null;
		String clear = "test";
		
		for(int i = 0 ; i <10 ; i++){
			
			String hashed = provider.digest(clear);
			
			assertFalse(clear.equals(hashed));
			assertTrue(hashed.length() == 40);
			
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
			
			assertTrue(hashed.length() == 40);
			
			assertFalse(hashes.contains(hashed));
			
			hashes.add(hashed);
			
		}
		
	}
	
	@Test
	public void testDigest384(){
		
		SHA256DigestProvider provider = new SHA256DigestProvider(TYPE.SHA384);
		String prevHash = null;
		String clear = "test";
		
		for(int i = 0 ; i <10 ; i++){
			
			String hashed = provider.digest(clear);
			
			assertFalse(clear.equals(hashed));
			assertTrue(hashed.length() == 96);
			
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
			
			assertTrue(hashed.length() == 96);
			
			assertFalse(hashes.contains(hashed));
			
			hashes.add(hashed);
			
		}
		
	}
	
	@Test
	public void testDigest512(){
		
		SHA256DigestProvider provider = new SHA256DigestProvider(TYPE.SHA512);
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
			
			assertTrue(hashed.length() == 128);
			
			assertFalse(hashes.contains(hashed));
			
			hashes.add(hashed);
			
		}
		
	}

}
