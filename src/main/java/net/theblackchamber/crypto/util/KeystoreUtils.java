package net.theblackchamber.crypto.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class KeystoreUtils {
	private static final String KEYSTORE_PASSWORD = "f42ecc4c507d43f9071c13491e3a3c6a";

	/**
	 * Method which will generate a random AES key and add it to a keystore.
	 * @param keystore
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws IOException
	 */
	public static void generateAESSecretKey(File keystore)
			throws NoSuchAlgorithmException, KeyStoreException,
			CertificateException, IOException {

		SecureRandom random = new SecureRandom();

		KeyGenerator keygen = KeyGenerator.getInstance("AES",new BouncyCastleProvider());
		keygen.init(256, random);
		
		SecretKey key = keygen.generateKey();
		
		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		FileInputStream fis = null;
		if(keystore.exists() && FileUtils.sizeOf(keystore) > 0){
			fis = new FileInputStream(keystore);
		}
		
		keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());

		KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(KEYSTORE_PASSWORD.toCharArray());
		KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(key);

		keyStore.setEntry("aes-key", secretKeyEntry, protectionParameter);
		if(fis != null){
			fis.close();
		}
		FileOutputStream fos = new FileOutputStream(keystore);
		
		keyStore.store(fos,KEYSTORE_PASSWORD.toCharArray());

		fos.close();
		
		
	}

	/**
	 * Method which will load a secret key from disk.
	 * @param keystore
	 * @return
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws UnrecoverableEntryException
	 */
	public static SecretKey getAESSecretKey(File keystore) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableEntryException{
		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		FileInputStream fis = null;
		if(!keystore.exists() || FileUtils.sizeOf(keystore) == 0){
			throw new FileNotFoundException();
		}
		fis = new FileInputStream(keystore);
		keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());
		KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(KEYSTORE_PASSWORD.toCharArray());
		KeyStore.SecretKeyEntry pkEntry = (KeyStore.SecretKeyEntry)keyStore.getEntry("aes-key", protectionParameter);
		try{
			return pkEntry.getSecretKey();
		}finally{
			fis.close();
		}
		
	}
	
}
