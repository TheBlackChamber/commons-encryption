package net.theblackchamber.crypto.constants;

public enum SupportedKeyGenAlgorithms {

	AES("AES"),TRIPLE_DES("DESede");
	
	private String name;
	
	private SupportedKeyGenAlgorithms(String name){
		this.name = name;
	}
	
	public String getName(){
		return name;
	}
	
}
