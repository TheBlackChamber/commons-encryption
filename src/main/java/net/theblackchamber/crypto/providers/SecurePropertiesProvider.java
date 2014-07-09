/**
 * 
 */
package net.theblackchamber.crypto.providers;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.util.InvalidPropertiesFormatException;
import java.util.Properties;

public class SecurePropertiesProvider extends Properties {

	private static final long serialVersionUID = 6795084558089471182L;

	/**
	 * Default constructor. Uses KEYSTORE_PATH system property to locate
	 * keystore on disk.
	 */
	public SecurePropertiesProvider() {
		super();
		// Load crypto
	}

	/**
	 * Constructor which specifies {@link Properties} defaults. Uses
	 * KEYSTORE_PATH system property to locate keystore on disk.
	 */
	public SecurePropertiesProvider(Properties defaults) {
		super(defaults);
		// Load crypto
	}

	@Override
	public synchronized void load(InputStream inStream) throws IOException {
		super.load(inStream);
		// Load crypto
	}

	@Override
	public synchronized void load(Reader reader) throws IOException {
		super.load(reader);
		// Load crypto
	}

	@Override
	public synchronized void loadFromXML(InputStream in) throws IOException,
			InvalidPropertiesFormatException {
		this.loadFromXML(in);
		// Load crypto
	}

}
