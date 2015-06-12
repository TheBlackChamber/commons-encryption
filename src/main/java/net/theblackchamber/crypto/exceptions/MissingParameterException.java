package net.theblackchamber.crypto.exceptions;

/**
 * Custom exception to be thrown when a parameter is expected to be passed to a
 * method but null or blank is found instead.
 * 
 * @author sminogue
 * 
 */
public class MissingParameterException extends Exception {
	
	private static final long serialVersionUID = 285094563007611726L;

	public MissingParameterException() {
		super();
	}

	public MissingParameterException(String message) {
		super(message);
	}

	public MissingParameterException(Throwable cause) {
		super(cause);
	}

	public MissingParameterException(String message, Throwable cause) {
		super(message, cause);
	}


}
