package net.theblackchamber.crypto.exceptions;

import org.junit.Test;

import static org.junit.Assert.*;

public class MissingParameterExceptionTest {

	@Test
	public void testConstructorEmptyConstructor(){
		try{
			
			MissingParameterException exception = new MissingParameterException();
			assertNotNull(exception);
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}

	@Test
	public void testConstructorMessageConstructor(){
		try{
			
			MissingParameterException exception = new MissingParameterException("MESSAGE");
			assertNotNull(exception);
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testConstructorThrowableConstructor(){
		try{
			
			MissingParameterException exception = new MissingParameterException(new Exception());
			assertNotNull(exception);
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testConstructorMessageAndThrowableConstructor(){
		try{
			
			MissingParameterException exception = new MissingParameterException("MESSAGE",new Exception());
			assertNotNull(exception);
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
		
}
