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
 * The above copyright notice and this permission notice shall be included in all
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
package net.theblackchamber.crypto.exceptions;

/**
 * Custom checked exception to be thrown when a key provider is instantiated
 * with a key of inappropriate size. Eg. AES supports key sizes 128, 192, 256.
 * Should a key of 1024 be passed to it this exception would be thrown.
 * 
 * @author sminogue
 * 
 */@Deprecated
public class UnsupportedKeySizeException extends Exception {

	public UnsupportedKeySizeException() {
		super();
	}

	public UnsupportedKeySizeException(String message) {
		super(message);
	}

	public UnsupportedKeySizeException(Throwable cause) {
		super(cause);
	}

	public UnsupportedKeySizeException(String message, Throwable cause) {
		super(message, cause);
	}

}
