package net.theblackchamber.crypto.constants;

public enum SupportedEncryptionAlgorithms {

	AES128("PBEWITHSHA256AND128BITAES-CBC-BC"),
	AES192("PBEWITHSHA192AND256BITAES-CBC-BC"),
	AES256("PBEWITHSHA256AND256BITAES-CBC-BC");

	private String algorithm;

	private SupportedEncryptionAlgorithms(String algorithm) {
		this.algorithm = algorithm;
	}

	public String getAlgorithm() {
		return algorithm;
	}

}
