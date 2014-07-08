/**
 * 
 */
package net.theblackchamber.key;

import java.io.Serializable;

public class SymetricSerializableKey implements Serializable{

	private static final long serialVersionUID = 7607337151682849683L;
	private String secretKey = null;

	public String getSecretKey() {
		return secretKey;
	}

	public void setSecretKey(String secretKey) {
		this.secretKey = secretKey;
	}
	
}
