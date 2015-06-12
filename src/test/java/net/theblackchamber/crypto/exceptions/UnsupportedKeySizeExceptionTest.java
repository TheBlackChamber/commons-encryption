package net.theblackchamber.crypto.exceptions;

import org.junit.Test;

import static org.junit.Assert.*;

public class UnsupportedKeySizeExceptionTest {

	@Test
	public void testConstructorEmptyConstructor(){
		try{
			
			UnsupportedKeySizeException exception = new UnsupportedKeySizeException();
			assertNotNull(exception);
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}

	@Test
	public void testConstructorMessageConstructor(){
		try{
			
			UnsupportedKeySizeException exception = new UnsupportedKeySizeException("MESSAGE");
			assertNotNull(exception);
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testConstructorThrowableConstructor(){
		try{
			
			UnsupportedKeySizeException exception = new UnsupportedKeySizeException(new Exception());
			assertNotNull(exception);
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testConstructorMessageAndThrowableConstructor(){
		try{
			
			UnsupportedKeySizeException exception = new UnsupportedKeySizeException("MESSAGE",new Exception());
			assertNotNull(exception);
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
		
}
