commons-encryption
==================

### Pre-Requisites
Prior to making use of the commons-encryption library it may be necessary to install the [Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files](http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html).

### Usage
In order to make use of the commons-encryption library you first need to download the jars from here on github, or alternatively if you use maven you are able to download the dependency from maven central repository.

###### Maven Dependency
```XML
<dependency>
	<groupId>net.theblackchamber</groupId>
	<artifactId>commons-encryption</artifactId>
	<version>2.0.0</version>
</dependency>
```

After the commons-encryption library has been added to your project usage is pretty straight forward. Generally the classes you will be interacting with will be in the implementations, util, and providers packages. Specific examples of use can be found in the [API](http://theblackchamber.github.io/commons-encryption/api) documents located on the [project website](http://theblackchamber.github.io/commons-encryption) and in the unit tests under src/test/java.


### Examples:
###### Key Generation
The following snippet of code is an example of generating a 256 bit AES key and adding it to a keystore on disk with the key entry name of "aes-key" and the keystore encrypted using the password "TEST".
```java
KeyConfig config = new KeyConfig(keyStoreFile, "TEST", 256, SupportedKeyGenAlgorithms.AES, "aes-key");
KeystoreUtils.generateSecretKey(config);

//Add additional key to the keystore.
config = new KeyConfig(keyStoreFile, "TEST", 192, SupportedKeyGenAlgorithms.DES, "des-key");
KeystoreUtils.generateSecretKey(config);
```

###### SecureProperties
SecureProperties is an attempt to provide a transparent extension of the native java Properties class which allows property values to be encrypted at rest. Be aware of the exceptions thrown by methods as described in the [API](http://theblackchamber.github.io/commons-encryption/api)... Methods throw a custom unchecked runtime exception. Also note that its possible to pass Key Password, Keystore Path, and Key Entry name to the SecureProperties constructor rather than specifying them in the properties file.
###### test.properties
```properties
entry-name=aes-key
keystore-password=changeit
key-path=/my/key/location
key1=My Unencrypted Property Value
key2-encrypted=FAB123DE7A012FCD
```

The following snippet of code is an example of loading a properties file from disk into a SecureProperties object which can be used in existing java classes.
```java
FileReader reader = new FileReader(propertiesFile);
Properties sProperties = new SecureProperties();
sProperties.load(reader);
String clearKey2 = sProperties.getProperty("key2-encrypted");
sProperties.setProperty("key3-unencrypted","cleartext value");
```

The following snippet of code is an example of configuring the SecureProperties by parameter rather than having configuration in the same file as the secured values (<b>This is the recommended use</b>)
```java
FileReader reader = new FileReader(propertiesFile);
SecureProperties sProperties = new SecureProperties(propertiesFile,keyfile.getPath(),"aes-key","TEST");
sProperties.load(reader);
String decryptedProperty = sProperties.getProperty("test-encrypted");
```

###### EncryptionProvider
If you find yourself needing to build your own "implementation" using encryption or just want to manually encrypt/decrypt values. The providers can be used directly.
```java
SecretKey key = KeystoreUtils.getSecretKey(keyfile, "aes-key", "TEST");
EncryptionProvider encryptionProvider = EncryptionProviderFactory.getProvider(key);
String cipherText = encryptionProvider.encode("clear text");
```

###### SecurePropertiesUtils
The SecurePropertiesUtils is a utility class primarily used to initially encrypt a clear text properties file in preperation of deploying it to a server. This is so that you can keep a clear text version in your project, edit it, and then easily in one step encrypt the fields which need to be secured and then deploy. Important to note that while a SecureProperties instance is returned the file IS changed on disk as well, the returned SecureProperties is just a convenience. Also note that its possible to pass Key Password, Keystore Path, and Key Entry name to the encryptPropertiesFile method rather than specifying them in the properties file.
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

###### Message Digest
SHA256 and Whirlpool are the currently implemented Digest Providers. Usage for both is the same:
```java
SHA256DigestProvider provider = new SHA256DigestProvider();
String hashedString = provider.digest("CLEARTEXT");
```

###### Further Examples
More examples of usage can be found in the src/test/java folder.



