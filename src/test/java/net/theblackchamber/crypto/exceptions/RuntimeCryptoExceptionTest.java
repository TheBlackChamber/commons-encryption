package net.theblackchamber.crypto.exceptions;

import org.junit.Test;

import static org.junit.Assert.*;

public class RuntimeCryptoExceptionTest {

	@Test
	public void testConstructorEmptyConstructor(){
		try{
			
			RuntimeCryptoException exception = new RuntimeCryptoException();
			assertNotNull(exception);
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}

	@Test
	public void testConstructorMessageConstructor(){
		try{
			
			RuntimeCryptoException exception = new RuntimeCryptoException("MESSAGE");
			assertNotNull(exception);
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testConstructorThrowableConstructor(){
		try{
			
			RuntimeCryptoException exception = new RuntimeCryptoException(new Exception());
			assertNotNull(exception);
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testConstructorMessageAndThrowableConstructor(){
		try{
			
			RuntimeCryptoException exception = new RuntimeCryptoException("MESSAGE",new Exception());
			assertNotNull(exception);
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testConstructorMessageAndThrowableAndBooleansConstructor(){
		try{
			
			RuntimeCryptoException exception = new RuntimeCryptoException("MESSAGE",new Exception(),false,false);
			assertNotNull(exception);
			
		}catch(Throwable t){
			t.printStackTrace();
			fail();
		}
	}
	
}
