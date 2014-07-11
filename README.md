commons-encryption
==================

### Pre-Requisites
Prior to making use of the commons-encryption library it may be necessary to install the [Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files](http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html). If you live in a jurisdiciton where you cannot make use of these unlimited strength encryption policy files you should still be able to make use of commons-encryption by specifying smaller key lengths to the keystore generator. 

### Usage
In order to make use of the commons-encryption library you first need to download the jars from here on github, or alternatively if you use maven you will soon be able to download the dependency from maven central repository.

###### Maven Dependency
```XML
<dependency>
	<groupId>net.theblackchamber</groupId>
	<artifactId>commons-encryption</artifactId>
	<version>.1</version>
</dependency>
```

After the commons-encryption library has been added to your project usage is pretty straight forward. Generally the classes you will be interacting with will be in the implementations, util, and providers packages. Specific examples of use can be found in the [API](http://sminogue.github.io/commons-encryption/api) documents located on the [project website](http://sminogue.github.io/commons-encryption) and in the unit tests under src/test/java.


### Examples:
###### Key Generation
The following snippet of code is an example of generating a 256 bit AES key and adding it to a keystore on disk with the key entry name of "aes-key" and the keystore encrypted using the password "TEST".
```java
KeyConfig config = new KeyConfig(keyStoreFile, "TEST", 256, SupportedAlgorithms.AES, "aes-key");
KeystoreUtils.generateAESSecretKey(config);
```

###### SecureProperties
SecureProperties is an attempt to provide a transparent extension of the native java Properties class which allows property values to be encrypted at rest. Be aware of the exceptions thrown by methods as described in the [API](http://sminogue.github.io/commons-encryption/api)... Methods throw a custom unchecked runtime exception.
###### test.properties
```properties
entry-name=aes-key
keystore-password=changeit
key-path=/my/key/location
key1=My Unencrypted Property Value
key2-encrypted=FAB123DE7A012FCD
```

The following snipped of code is an example of loading a properties file from disk into a SecureProperties object which can be used in existing java classes.
```java
FileReader reader = new FileReader(propertiesFile);
Properties sProperties = new SecureProperties();
sProperties.load(reader);
String clearKey2 = sProperties.getProperty('key2-encrypted');
sProperties.setProperty('key3-unencrypted','cleartext value');
```

###### AESEncryptionProvider
If you find yourself needing to build your own "implementation" using encryption or just want to manually encrypt/decrypt values. The providers can be used directly.
```java
SecretKey key = KeystoreUtils.getAESSecretKey(keyfile, "aes-key", "TEST");
AESEncryptionProvider encryptionProvider = new AESEncryptionProvider(key);
String cipherText = encryptionProvider.encode("clear text");
```

###### SecurePropertiesUtils
The SecurePropertiesUtils is a utility class primarily used to initially encrypt a clear text properties file in preperation of deploying it to a server. This is so that you can keep a clear text version in your project, edit it, and then easily in one step encrypt the fields which need to be secured and then deploy. Important to note that while a SecureProperties instance is returned the file IS changed on disk as well, the returned SecureProperties is just a convenience.
```properties
entry-name=aes-key
keystore-password=changeit
key-path=/my/key/location
key1=My Unencrypted Property Value
key2-unencrypted=This Will Be Encrypted
```
```java
SecureProperties sProperties = SecurePropertiesUtils.encryptPropertiesFile(propertiesFile);
```



