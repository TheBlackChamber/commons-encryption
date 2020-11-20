/**
 * The MIT License (MIT)
 * 
 * Copyright (c) 2014 Seamus Minogue
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package net.theblackchamber.crypto.implementations;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.RandomStringUtils;

import net.theblackchamber.crypto.exceptions.MissingParameterException;
import net.theblackchamber.crypto.providers.EncryptionProvider2;

/**
 * Class which will provide functionality to encrypt and decrypt files.
 * 
 * @author sminogue
 * 
 */
public class FileEncryptor2 {

	private EncryptionProvider2 encryptionProvider;

	public FileEncryptor2(EncryptionProvider2 provider) throws MissingParameterException {

		if (provider == null) {
			throw new MissingParameterException();
		}

		this.encryptionProvider = provider;
	}

	/**
	 * Encrypt a file. This will replace the specified file with an encrypted
	 * version.
	 * 
	 * @param file
	 * @throws IOException 
	 * @throws MissingParameterException 
	 * @throws GeneralSecurityException 
	 */
	public void encryptFile(File file) throws MissingParameterException, IOException, GeneralSecurityException {
		encryptFile(file, true);
	}

	/**
	 * Encrypt a file.
	 * 
	 * @param file
	 *            The file to encrypt
	 * @param replace
	 *            True - Replace the specified file with the encrypted version.
	 *            False - Keep the unencrypted file.
	 * @throws MissingParameterException 
	 * @throws IOException 
	 * @throws GeneralSecurityException 
	 */
	public void encryptFile(File file, boolean replace) throws MissingParameterException, IOException, GeneralSecurityException {

		if(file == null || !file.exists()){
			throw new MissingParameterException("File not specified or file does not exist.");
		}
		
		FileInputStream fis = new FileInputStream(file);
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream(1000);
		
		encryptStream(fis, baos);
		
		File tmpEncrypted = File.createTempFile("commonsencryption", RandomStringUtils.randomAlphanumeric(10));
		
		if(!tmpEncrypted.exists()){
			throw new IOException("Failed to encrypt file.");
		}
		
		FileOutputStream fos = new FileOutputStream(tmpEncrypted);
		
		IOUtils.write(baos.toByteArray(),fos);
		
		fos.close();
		
		if(replace){
			File bkpFile = FileUtils.getFile(file.getAbsolutePath() + ".bkp");
			FileUtils.moveFile(file, bkpFile);
			
			try{
			
				FileUtils.moveFile(tmpEncrypted, FileUtils.getFile(file.getAbsolutePath()));
			
			}catch(IOException e){
				throw new IOException("Failed to encrypt file. Existing file saved with \".bkp\": " + e.getMessage(),e);
			}
			
			bkpFile.delete();
			
		}else{
			
			FileUtils.moveFile(tmpEncrypted, FileUtils.getFile(file.getAbsolutePath() + ".encrypted"));
			
		}
		
	}

	/**
	 * Encrypt the contents of an input stream and write the encrypted data to
	 * the output stream.
	 * 
	 * @param clearInputStream
	 *            Input stream containing the data to be encrypted.
	 * @param encryptedOutputStream
	 *            Output stream which the encrypted data will be written to.
	 * @throws IOException
	 * @throws MissingParameterException
	 * @throws GeneralSecurityException 
	 */
	public void encryptStream(InputStream clearInputStream, OutputStream encryptedOutputStream) throws IOException, MissingParameterException, GeneralSecurityException {

		byte[] clearBytes = IOUtils.toByteArray(clearInputStream);

		byte[] cipherBytes = encryptionProvider.encrypt(clearBytes);

		encryptedOutputStream.write(cipherBytes);

		encryptedOutputStream.flush();
		
		encryptedOutputStream.close();
		
	}

}
