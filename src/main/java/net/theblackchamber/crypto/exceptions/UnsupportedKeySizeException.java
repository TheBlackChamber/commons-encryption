package net.theblackchamber.crypto.exceptions;

/**
 * Custom checked exception to be thrown when a key provider is instantiated
 * with a key of inappropriate size. Eg. AES supports key sizes 128, 192, 256.
 * Should a key of 1024 be passed to it this exception would be thrown.
 * 
 * @author sminogue
 * 
 */
public class UnsupportedKeySizeException extends Exception {

	public UnsupportedKeySizeException() {
		super();
	}

	public UnsupportedKeySizeException(String message) {
		super(message);
	}

	public UnsupportedKeySizeException(Throwable cause) {
		super(cause);
	}

	public UnsupportedKeySizeException(String message, Throwable cause) {
		super(message, cause);
	}

}
