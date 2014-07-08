package net.theblackchamber.crypto.providers;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.SimplePBEConfig;
import org.jasypt.salt.RandomSaltGenerator;

import net.theblackchamber.crypto.key.SymetricSerializableKey;

public class AESEncryptionProvider {

	private SymetricSerializableKey key;
	StandardPBEStringEncryptor encryptor;
	
	public AESEncryptionProvider(final SymetricSerializableKey key){
		super();
		this.key = key;
		
		//Configure Encryptor
		SimplePBEConfig config = new SimplePBEConfig();
		config.setAlgorithm("PBEWITHSHA256AND128BITAES-CBC-BC");
		config.setKeyObtentionIterations(10);
		config.setPassword(key.getSecretKey());
		config.setProvider(new BouncyCastleProvider());
		config.setSaltGenerator(new RandomSaltGenerator());
		
		encryptor = new StandardPBEStringEncryptor();
		encryptor.setConfig(config);
		encryptor.setStringOutputType("hexadecimal");
	}
	
	public String decrypt(String cipherText){
		return encryptor.decrypt(cipherText);
	}
	
	public String encrypt(String clearText){
		return encryptor.encrypt(clearText);
	}
	
}
