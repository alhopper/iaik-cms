// Copyright (C) 2002 IAIK
// http://jce.iaik.tugraz.at
//
// Copyright (C) 2003 Stiftung Secure Information and 
//                    Communication Technologies SIC
// http://jce.iaik.tugraz.at
//
// All rights reserved.
//
// This source is provided for inspection purposes and recompilation only,
// unless specified differently in a contract with IAIK. This source has to
// be kept in strict confidence and must not be disclosed to any third party
// under any circumstances. Redistribution in source and binary forms, with
// or without modification, are <not> permitted in any case!
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.
//
// $Header: /IAIK-CMS/current/src/demo/cms/envelopedData/FileEncryptionDemo.java 8     23.08.13 14:22 Dbratko $
// $Revision: 8 $
//

package demo.cms.envelopedData;

import iaik.asn1.UTF8String;
import iaik.asn1.structures.AlgorithmID;
import iaik.cms.CMSAlgorithmID;
import iaik.cms.ContentInfoStream;
import iaik.cms.EnvelopedDataStream;
import iaik.cms.PasswordRecipientInfo;
import iaik.cms.RecipientInfo;
import iaik.security.random.SecRandom;
import iaik.security.spec.PBEKeyAndParameterSpec;
import iaik.utils.Util;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

import javax.crypto.SecretKey;

import demo.DemoUtil;

/**
 * This class shows how to use the CMS {@link iaik.cms.PasswordRecipientInfo
 * PasswordRecipientInfo} type for password based encrypting the contents of 
 * a file (and later decrypting it again) with the CMS {@link iaik.cms.EnvelopedDataStream
 * EnvelopedDataStream} EnvelopedData} content type.
 * <p>
 * The contents is encrypted using the AES cipher. For dereiving the key
 * encryption key from the password, the PKCS#5 PBKDF2 key derivation function
 * is used. The content encryption key is decrypted with AES, too. 
 * <p>
 * You can modify this demo to use any other supported algorithm(s). Or
 * you can use it with PBKDF2/AES for encrypting a file simply
 * by calling:
 * <pre>
 * // the file to be encrypted
 * String dataFile = ...;
 * // the file to which to write the encrypted data
 * String encryptedFile = ...;
 * // password 
 * char[] password = ...;
 * // encrypt file
 * FileEncryption fe = new FileEncryption();
 * fe.encrypt(dataFile, encryptedFile, password);
 * </pre>
 * 
 * Or decrypting a file:
 * 
 * <pre>
 * // the encrypted file
 * String encryptedFile = ...;
 * // the file to which to write the decrypted data
 * String decryptedFile = ...;
 * // password 
 * char[] password = ...;
 * // drcrypt file
 * FileEncryption fe = new FileEncryption();
 * fe.decrypt(encryptedFile, decryptedFile, password);
 * </pre>
 * 
 * @see iaik.cms.EnvelopedDataStream
 * @see iaik.cms.EnvelopedData
 * @see iaik.cms.EnvelopedDataOutputStream
 * @see iaik.cms.PasswordRecipientInfo
 * 
 * @author Dieter Bratko
 */
public class FileEncryptionDemo {

  /**
   * Default constructor.
   */
  public FileEncryptionDemo() {
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                   File encryption/decryption demo                              *");
    System.out.println("*    (shows how to use the PasswordRecipientInfo type for encrypting a file)     *");
    System.out.println("**********************************************************************************");
    System.out.println();
    
  }

 
  /**
   * Uses the given password to encrypt the contents from <code>inFile</code>
   * and write the encryption result to <code>outFile</code>.
   * The contents is encrypted using the AES cipher. For dereiving the key
   * encryption key from the password, the PKCS#5 PBKDF2 key derivation function
   * is used. The content encryption key is decrypted with AES, too. 
   *
   * @param inFile the file from which to read the encrypted (enveloped) data
   * @param outFile the file to which to write the decrypted data
   * @param password the password to be used for decryption
   *
   * @exception Exception if an error occurs
   */
  public void encrypt(String inFile,
                      String outFile,
                      char[] password) 
    throws Exception {

    // stream for reading the data from the file to be encrypted
    InputStream is = null;
    // stream for writing the encrypted data to a file
    OutputStream os = null;
    
    // key derivation function (PBKDF2)
    AlgorithmID keyDerivationAlg = (AlgorithmID)AlgorithmID.pbkdf2.clone();
    // key encryption algorithm (PWRI-KEK)
    AlgorithmID keyEncryptionAlg = (AlgorithmID)CMSAlgorithmID.pwri_kek.clone();
    // for PWRI-KEK set the kek encryption algorithm parameter (AES)
    AlgorithmID kekEncryptionAlg = (AlgorithmID)AlgorithmID.aes128_CBC.clone();
    keyEncryptionAlg.setParameter(kekEncryptionAlg.toASN1Object());
    // content encryption algorithm
    AlgorithmID cekAlg = (AlgorithmID)AlgorithmID.aes128_CBC.clone();
    
    // parameters for key derivation
    int kekLen = 16;  // we use AES as kek algorithm
    int iterationCount = 2000; 
    byte[] salt = new byte[16];
    SecureRandom random = SecRandom.getDefault();
    random.nextBytes(salt);
    PBEKeyAndParameterSpec keyDerivationParamSpec =
      new PBEKeyAndParameterSpec(UTF8String.getUTF8EncodingFromCharArray(password),
                                 salt,
                                 iterationCount,
                                 kekLen); 
    
    try {
      
      is = new BufferedInputStream(new FileInputStream(inFile));
      
      // create EnvelopedData for encrypting the data with the content encryption algorithm
      EnvelopedDataStream envelopedData = new EnvelopedDataStream(is, cekAlg);
      
      // create the PasswordRecipientInfo
      PasswordRecipientInfo pri = new PasswordRecipientInfo(password,
                                                            keyDerivationAlg,
                                                            keyDerivationParamSpec,
                                                            keyEncryptionAlg,                               
                                                            null);
      // set the RecipientInfo
      envelopedData.setRecipientInfos(new RecipientInfo[] { pri });
      envelopedData.setBlockSize(2048);
      // wrap into ContentInfo
      ContentInfoStream cis = new ContentInfoStream(envelopedData);
      
      // encrypt to file
      os = new BufferedOutputStream(new FileOutputStream(outFile));
      cis.writeTo(os);
       
    } finally {
      if (is != null) {
        try {
          is.close();
        } catch (IOException ex) {
          // ignore
        }
      }
      if (os != null) {
        try {
          os.close();
        } catch (IOException ex) {
          // ignore
        }
      }
    }
   
  }

  /**
   * Uses the given password to decrypt the contents from <code>inFile</code>
   * and write the it to <code>outFile</code>. 
   *
   * @param inFile the file from which to read the encrypted (enveloped) data
   * @param outFile the file to which to write the decrypted data
   * @param password the password to be used for decryption
   *
   * @exception Exception if an error occurs
   */
  public void decrypt(String inFile, String outFile, char[] password)
    throws Exception {

    // stream for reading the encrypted data from a file
    InputStream is = null;
    // stream for writing the decrypted data to a file
    OutputStream os = null;
    
    try {
      
      is = new BufferedInputStream(new FileInputStream(inFile));
      
      // create EnvelopedData 
      EnvelopedDataStream envelopedData = new EnvelopedDataStream(is);
      
      // get PasswordRecipientInfo and decrypt the cek
      PasswordRecipientInfo recipient = (PasswordRecipientInfo)envelopedData.getRecipientInfos()[0];
      SecretKey cek = recipient.decryptKey(password); 
      // setup cipher for content decryption
      envelopedData.setupCipher(cek);
      InputStream decrypted = envelopedData.getInputStream();
      // decrypt data to file
      os = new BufferedOutputStream(new FileOutputStream(outFile));
      Util.copyStream(decrypted, os, null);
      
    } finally {
      if (is != null) {
        try {
          is.close();
        } catch (IOException ex) {
          // ignore
        }
      }
      if (os != null) {
        try {
          os.close();
        } catch (IOException ex) {
          // ignore
        }
      }
    }
    
  }


  /**
   * Starts the demo.
   */
  public void start() {
    // the file to be encrypted
    String dataFile = "test.html";
    // the file to which to write the encrypted data
    String encryptedFile = "encrypted.dat";
    // the file to which to write the decrypted data
    String decryptedFile = "decrypted.html";
    
    // password (in practice use a more secure one!)
    char[] password = { 't', 'o', 'p', 'S', 'e', 'c', 'r', 'e', 't' };
    
    try {
      
      // encrypt file
      System.out.println("Encrypt data from file " + dataFile + " to file " + encryptedFile);
      encrypt(dataFile, encryptedFile, password);

      // decrypt file
      System.out.println("Decrypt data from file " + encryptedFile + " to file " + decryptedFile);
      decrypt(encryptedFile, decryptedFile, password);
      
    } catch (Exception ex) {  
      ex.printStackTrace();
      throw new RuntimeException(ex.toString());  
    } finally {
      for (int i = 0; i < password.length; i++) { 
        password[i] = '\u0000';
      }  
    }

  }


  /**
   * Main method.
   *
   * @exception Exception
   *            if some error occurs 
   */
  public static void main(String argv[]) throws Exception {

   	DemoUtil.initDemos();

    (new FileEncryptionDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
