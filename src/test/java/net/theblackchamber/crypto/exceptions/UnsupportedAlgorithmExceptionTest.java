package net.theblackchamber.crypto.exceptions;

import org.junit.Test;

import static org.junit.Assert.*;

public class UnsupportedAlgorithmExceptionTest {

	@Test
	public void testConstructorEmptyConstructor(){
		try{
			
			UnsupportedAlgorithmException exception = new UnsupportedAlgorithmException();
			assertNotNull(exception);
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}

	@Test
	public void testConstructorMessageConstructor(){
		try{
			
			UnsupportedAlgorithmException exception = new UnsupportedAlgorithmException("MESSAGE");
			assertNotNull(exception);
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testConstructorThrowableConstructor(){
		try{
			
			UnsupportedAlgorithmException exception = new UnsupportedAlgorithmException(new Exception());
			assertNotNull(exception);
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testConstructorMessageAndThrowableConstructor(){
		try{
			
			UnsupportedAlgorithmException exception = new UnsupportedAlgorithmException("MESSAGE",new Exception());
			assertNotNull(exception);
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
		
}
