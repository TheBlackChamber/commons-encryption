package net.theblackchamber.crypto.providers.symmetric;

import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;

import net.theblackchamber.crypto.providers.EncryptionProvider2;

public class AESEncryptionProvider2 extends EncryptionProvider2{

	
	
	public AESEncryptionProvider2(KeysetHandle keysetHandle) {
		super(keysetHandle);
	}

	@Override
	protected byte[] performEncryption(byte[] data, byte[] associated) throws GeneralSecurityException {
		Aead aead = getKey().getPrimitive(Aead.class);
		return aead.encrypt(data, associated);
	}

	@Override
	protected byte[] performDecryption(byte[] data, byte[] associated) throws GeneralSecurityException {
		Aead aead = getKey().getPrimitive(Aead.class);
		return aead.decrypt(data, associated);
	}
}
