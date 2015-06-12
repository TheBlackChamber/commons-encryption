package net.theblackchamber.crypto.exceptions;

/**
 * Checked exception used to signal that the algorithm specified is not
 * available or that the key attempting to be used with an algorithm doesnt
 * support it.
 * 
 * @author sminogue
 * 
 */
public class UnsupportedAlgorithmException extends Exception {

	private static final long serialVersionUID = -2652604359559424403L;

	public UnsupportedAlgorithmException() {
		super();
	}

	public UnsupportedAlgorithmException(String message) {
		super(message);
	}

	public UnsupportedAlgorithmException(Throwable cause) {
		super(cause);
	}

	public UnsupportedAlgorithmException(String message, Throwable cause) {
		super(message, cause);
	}


}
