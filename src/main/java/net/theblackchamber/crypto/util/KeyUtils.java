package net.theblackchamber.crypto.util;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.util.encoders.Hex;
import org.jasypt.digest.config.SimpleDigesterConfig;
import org.jasypt.salt.RandomSaltGenerator;
import org.jasypt.util.password.ConfigurablePasswordEncryptor;

import net.theblackchamber.crypto.key.SymetricSerializableKey;

public class KeyUtils {

	private static final Log log = LogFactory.getLog(KeyUtils.class);

	/**
	 * Utility method which will create a new random
	 * {@link SymetricSerializableKey}
	 * 
	 * @return
	 */
	public static SymetricSerializableKey generateSymetricSerializableKey() {
		// Securely create 32byte random password
		SecureRandom random = new SecureRandom();
		byte bytes[] = new byte[32];
		random.nextBytes(bytes);
		String randomHex = Hex.toHexString(bytes);

		// Create digest configuration
		SimpleDigesterConfig config = new SimpleDigesterConfig();
		config.setAlgorithm("SHA-512");
		config.setIterations(10000);
		config.setSaltGenerator(new RandomSaltGenerator());
		config.setSaltSizeBytes(16);

		// Create digester
		ConfigurablePasswordEncryptor configurablePasswordEncryptor = new ConfigurablePasswordEncryptor();
		configurablePasswordEncryptor.setConfig(config);

		// Hash random password
		String encryptedPassword = configurablePasswordEncryptor
				.encryptPassword(randomHex);

		// Create and return encryption key.
		SymetricSerializableKey key = new SymetricSerializableKey();
		key.setSecretKey(encryptedPassword);
		return key;
	}

	/**
	 * Utility method which will write a {@link SymetricSerializableKey} key to
	 * disk.
	 * 
	 * @param keyFile
	 * @param key
	 */
	public static void writeSymetricSerializableKey(File keyFile,
			SymetricSerializableKey key) {
		ObjectOutput output = null;
		try {
			OutputStream file = new FileOutputStream(keyFile);
			OutputStream buffer = new BufferedOutputStream(file);
			output = new ObjectOutputStream(buffer);
			output.writeObject(key);
		} catch (Exception e) {
			log.error(
					"Failed to write symetric key to disk: " + e.getMessage(),
					e);
		} finally {
			if (output != null) {
				try {
					output.flush();
					output.close();
				} catch (Exception e) {
					log.warn(
							"Failed to properly close keyfile: "
									+ e.getMessage(), e);
				}
			}

		}
	}

	/**
	 * Utility method which will read a {@link SymetricSerializableKey} key from
	 * disk.
	 * 
	 * @param keyFile
	 * @param key
	 */
	public static SymetricSerializableKey readSymetricSerializableKey(
			File keyFile) {
		ObjectInput input = null;
		try {
			InputStream file = new FileInputStream(keyFile);
			InputStream buffer = new BufferedInputStream(file);
			input = new ObjectInputStream(buffer);

			return (SymetricSerializableKey) input.readObject();

		} catch (Exception e) {
			log.error(
					"Failed to write symetric key to disk: " + e.getMessage(),
					e);
			return null;
		} finally {
			if (input != null) {
				try {
					input.close();
				} catch (Exception e) {
					log.warn(
							"Failed to properly close keyfile: "
									+ e.getMessage(), e);
				}
			}

		}
	}

}
