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
// $Header: /IAIK-CMS/current/src/demo/cms/envelopedData/PasswordRecipientInfoDemo.java 27    23.08.13 14:22 Dbratko $
// $Revision: 27 $
//

package demo.cms.envelopedData;

import iaik.asn1.UTF8String;
import iaik.asn1.structures.AlgorithmID;
import iaik.cms.CMSAlgorithmID;
import iaik.cms.CMSException;
import iaik.cms.ContentInfo;
import iaik.cms.ContentInfoStream;
import iaik.cms.EncryptedContentInfo;
import iaik.cms.EncryptedContentInfoStream;
import iaik.cms.EnvelopedData;
import iaik.cms.EnvelopedDataStream;
import iaik.cms.PasswordRecipientInfo;
import iaik.cms.RecipientInfo;
import iaik.security.random.SecRandom;
import iaik.security.spec.PBEKeyAndParameterSpec;
import iaik.utils.Util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.SecretKey;

import demo.DemoUtil;

/**
 * This class shows the usage of the CMS RecipientInfo type {@link iaik.cms.PasswordRecipientInfo
 * PasswordRecipientInfo} as specified by <a href = http://www.ietf.org/rfc/rfc5652.txt" target="_blank"> RFC 5652</a>.
 * 
 * @author Dieter Bratko
 */
public class PasswordRecipientInfoDemo {

  
  // secure random number generator
  SecureRandom random;

  /**
   * Default constructor.
   */
  public PasswordRecipientInfoDemo() {
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                   PasswordRecipientInfoDemo                                    *");
    System.out.println("*    (shows the usage of the CMS PasswordRecipientInfo type implementation)      *");
    System.out.println("**********************************************************************************");
    System.out.println();
    
    random = SecRandom.getDefault();
  }

 
  /**
   * Creates a CMS <code>EnvelopedData</code> with a PasswordRecipientInfo
   * and wraps it into a ContentInfo (stream implementation).
   *
   * @param message the message to be enveloped, as byte representation
   * @param password the password from which to derive the key encryption key (kek)
   * @param keyDerivationAlg the key derivation function to be used for deriving the kek
   * @param keyDerivatoinParamSpec any parameters required by the key derivation function
   * @param keyEncrAlg the ID of the key-encryption (key-wrap) algorithm to be used
   *                   for encrypting the content-encryption key
   * @param keyEncrParams any algorithm parameters to be used for intializing the 
   *                          key wrap cipher
   * @return the encoded ContentInfo containing the EnvelopedData object just created
   *
   * @exception CMSException if the <code>EnvelopedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createEnvelopedDataStream(byte[] message,
                                          char[] password,
                                          AlgorithmID keyDerivationAlg,
                                          AlgorithmParameterSpec keyDerivatoinParamSpec,
                                          AlgorithmID keyEncrAlg,                               
                                          AlgorithmParameters keyEncrParams) 
    throws CMSException, IOException {

    EnvelopedDataStream envelopedData;

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);
    // create a new EnvelopedData object encrypted with TripleDES CBC
    try {
      envelopedData = new EnvelopedDataStream(is, (AlgorithmID)AlgorithmID.des_EDE3_CBC.clone());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Cannot init EnvelopedDataStream: " + ex.toString());
    }

    // create the PasswordRecipientInfo
    PasswordRecipientInfo pri;
    try {
      pri = new PasswordRecipientInfo(password,
                                      keyDerivationAlg,
                                      keyDerivatoinParamSpec,
                                      keyEncrAlg,                               
                                      keyEncrParams);
    } catch (Exception ex) {
      throw new CMSException("Cannot create PasswordRecipientInfo: " + ex.toString());   
    }    
        
    
    // specify the recipients of the encrypted message
    RecipientInfo[] recipients = { pri };
    envelopedData.setRecipientInfos(recipients);
    // return the EnvelopedDate as DER encoded byte array with block size 2048
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    envelopedData.setBlockSize(2048);
    ContentInfoStream cis = new ContentInfoStream(envelopedData);
    cis.writeTo(os);
    return os.toByteArray();
  }

  /**
   * PBE based decrypts the encrypted content of the given EnvelopedData object 
   * and returns the decrypted (= original) message (stream implementation).
   *
   * @param encoding the encoded ContentInfo containing an EnvelopedData object
   * @param password the password from which to derive the key-encryption key (kek)
   *                 to be used for decrypting the content-encryption key (cek)
   * @param cekAlgName the name of the cek (content encryption key) algorithm
   *
   * @return the recovered message, as byte array
   * @exception CMSException if the message cannot be recovered
   * @exception IOException if an I/O error occurs
   */
  public byte[] getEnvelopedDataStream(byte[] encoding, char[] password, String cekAlgName) throws CMSException, IOException {

    // create the EnvelopedData object from a DER encoded byte array
    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    EnvelopedDataStream envelopedData = new EnvelopedDataStream(is);

    System.out.println("Information about the encrypted data:");
    EncryptedContentInfoStream eci = (EncryptedContentInfoStream)envelopedData.getEncryptedContentInfo();
    System.out.println("Content type: "+eci.getContentType().getName());
    System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());

    System.out.println("\nInformation about the RecipientInfo :");
    PasswordRecipientInfo recipient = (PasswordRecipientInfo)envelopedData.getRecipientInfos()[0];
    System.out.println(recipient);

    // decrypt the message
    try {
      SecretKey cek = recipient.decryptKey(password, cekAlgName); 
      envelopedData.setupCipher(cek);
      InputStream decrypted = envelopedData.getInputStream();
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      Util.copyStream(decrypted, os, null);

      return os.toByteArray();

    } catch (Exception ex) {
      throw new CMSException("Cannot decrypt message. " + ex.toString());
    }
  }


  /**
   * Creates a CMS <code>EnvelopedData</code> with a PasswordRecipientInfo
   * and wraps it into a ContentInfo.
   *
   * @param message the message to be enveloped, as byte representation
   * @param password the password from which to derive the key encryption key (kek)
   * @param keyDerivationAlg the key derivation function to be used for deriving the kek
   * @param keyDerivatoinParamSpec any parameters required by the key derivation function
   * @param keyEncrAlg the ID of the key-encryption (key-wrap) algorithm to be used
   *                   for encrypting the content-encryption key
   * @param keyEncrParams any algorithm parameters to be used for intializing the 
   *                          key wrap cipher
   * @return the encoded ContentInfo containing the EnvelopedData object just created
   *
   * @exception CMSException if the <code>EnvelopedData</code> object cannot
   *                          be created
   */
  public byte[] createEnvelopedData(byte[] message, 
                                    char[] password,
                                    AlgorithmID keyDerivationAlg,
                                    AlgorithmParameterSpec keyDerivatoinParamSpec,
                                    AlgorithmID keyEncrAlg,                               
                                    AlgorithmParameters keyEncrParams) 
    throws CMSException {

    EnvelopedData envelopedData;

    // create a new EnvelopedData object encrypted with TripleDES CBC
    try {
      envelopedData = new EnvelopedData(message, (AlgorithmID)AlgorithmID.des_EDE3_CBC.clone());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("No implementation for Triple-DES-CBC.");
    }

    // create the PasswordRecipientInfo
    PasswordRecipientInfo pri;
    try {
      pri = new PasswordRecipientInfo(password,
                                      keyDerivationAlg,
                                      keyDerivatoinParamSpec,
                                      keyEncrAlg,                               
                                      keyEncrParams);
    } catch (Exception ex) {
      throw new CMSException("Cannot create PasswordRecipientInfo: " + ex.toString());   
    }    
        
    
    // specify the recipients of the encrypted message
    RecipientInfo[] recipients = { pri };
    envelopedData.setRecipientInfos(recipients);
    
    // wrap into contentInfo
    ContentInfo ci = new ContentInfo(envelopedData);
    // return the EnvelopedDate as DER encoded byte array
    return ci.toByteArray();
  }

  /**
   * PBE based decrypts the encrypted content of the given EnvelopedData object 
   * and returns the decrypted (= original) message.
   *
   * @param encoding the encoded ContentInfo containing an EnvelopedData object
   * @param password the password from which to derive the key-encryption key (kek)
   *                 to be used for decrypting the content-encryption key (cek)
   * @param cekAlgName the name of the cek (content encryption key) algorithm
   *
   * @return the recovered message, as byte array
   *
   * @exception CMSException if the message cannot be recovered
   * @exception IOException if an I/O error occurs
   */
  public byte[] getEnvelopedData(byte[] encoding, char[] password, String cekAlgName) throws CMSException, IOException {
    
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);

    EnvelopedData envelopedData = new EnvelopedData(is);

    System.out.println("Information about the encrypted data:");
    EncryptedContentInfo eci = (EncryptedContentInfo)envelopedData.getEncryptedContentInfo();
    System.out.println("Content type: "+eci.getContentType().getName());
    System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());

    System.out.println("\nInformation about the RecipientInfo :");
    PasswordRecipientInfo recipient = (PasswordRecipientInfo)envelopedData.getRecipientInfos()[0];
    System.out.println(recipient);

    // decrypt the message
    try {
      SecretKey cek = recipient.decryptKey(password, cekAlgName); 
      envelopedData.setupCipher(cek);
      return envelopedData.getContent();

    } catch (Exception ex) {
      throw new CMSException("Cannot decrypt message: " + ex.toString());
    }
  }
  


  /**
   * Starts the demo.
   */
  public void start() {
     // the test message
    String m = "This is the test message.";
    System.out.println("Test message: \""+m+"\"");
    System.out.println();
    byte[] message = m.getBytes();
    
    // the password
    char[] password = "topSecret".toCharArray();

    try {
      byte[] encodedEnvelopedData;
      byte[] receivedMessage = null;
      
      int kekLen = 24;  // we use TripleDES as kek algorithm
      int iterationCount = 2000; 
      byte[] salt = new byte[16];
      random.nextBytes(salt);
      PBEKeyAndParameterSpec keyDerivationParamSpec =
        new PBEKeyAndParameterSpec(UTF8String.getUTF8EncodingFromCharArray(password),
                                   salt,
                                   iterationCount,
                                   kekLen); 

      
      System.out.println("Stream implementation demo");
      System.out.println("===========================");

      // the stream implementation
      // test CMS EnvelopedDataStream
      //
      System.out.println("\nEnvelopedDataStream demo [create]:\n");
      // key derivation function
      AlgorithmID keyDerivationAlg = (AlgorithmID)AlgorithmID.pbkdf2.clone();
      // key encryption algorithm
      AlgorithmID keyEncryptionAlg = (AlgorithmID)CMSAlgorithmID.pwri_kek.clone();
      // for PWRI-KEK set the kek encryption algorithm parameter
      AlgorithmID kekEncryptionAlg = (AlgorithmID)AlgorithmID.des_EDE3_CBC.clone();
      keyEncryptionAlg.setParameter(kekEncryptionAlg.toASN1Object());
      // the name of the content encryption algorithm
      String cekAlgName = "DESede";
      // we can use null as password since it is already set in keyDerivationParamSpec
      encodedEnvelopedData = createEnvelopedDataStream(message,
                                                       null,
                                                       (AlgorithmID)keyDerivationAlg.clone(),
                                                       keyDerivationParamSpec,
                                                       keyEncryptionAlg,
                                                       null);
      // transmit data
      System.out.println("\nEnvelopedDataStream demo [parse]:\n");
      // user1 means index 0 (hardcoded for this demo)
      receivedMessage = getEnvelopedDataStream(encodedEnvelopedData, password, cekAlgName);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));

      // the non-stream implementation
      System.out.println("\nNon-stream implementation demo");
      System.out.println("===============================");
      
      
      //
      // test CMS EnvelopedData
      //
      System.out.println("\nEnvelopedData demo [create]:\n");
      // key derivation function
      keyDerivationAlg = (AlgorithmID)AlgorithmID.pbkdf2.clone();
      // key encryption algorithm
      keyEncryptionAlg = (AlgorithmID)CMSAlgorithmID.pwri_kek.clone();
      // for PWRI-KEK set the kek encryption algorithm parameter
      kekEncryptionAlg = (AlgorithmID)AlgorithmID.des_EDE3_CBC.clone();
      keyEncryptionAlg.setParameter(kekEncryptionAlg.toASN1Object());
      // the name of the content encryption algorithm
      cekAlgName = "DESede";
      // we can use null as password since it is already set in keyDerivationParamSpec
      encodedEnvelopedData = createEnvelopedData(message,
                                                 null,
                                                 keyDerivationAlg,
                                                 keyDerivationParamSpec,
                                                 keyEncryptionAlg,
                                                 null);
      // transmit data
      System.out.println("\nEnvelopedData demo [parse]:\n");
      // user1 means index 0 (hardcoded for this demo)
      receivedMessage = getEnvelopedData(encodedEnvelopedData, password, cekAlgName);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));



      System.out.println("Ready!");



   	} catch (Exception ex) {
   	  ex.printStackTrace();
   	  throw new RuntimeException(ex.toString());
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

    (new PasswordRecipientInfoDemo()).start();

    DemoUtil.waitKey();
  }
}
