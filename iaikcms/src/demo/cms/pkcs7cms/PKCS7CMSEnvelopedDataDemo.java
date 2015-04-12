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
// $Header: /IAIK-CMS/current/src/demo/cms/pkcs7cms/PKCS7CMSEnvelopedDataDemo.java 18    23.08.13 14:27 Dbratko $
// $Revision: 18 $
//

package demo.cms.pkcs7cms;

import iaik.asn1.ASN1Object;
import iaik.asn1.structures.AlgorithmID;
import iaik.cms.CMSException;
import iaik.cms.EncryptedContentInfo;
import iaik.cms.EncryptedContentInfoStream;
import iaik.cms.EnvelopedData;
import iaik.cms.EnvelopedDataStream;
import iaik.cms.KeyTransRecipientInfo;
import iaik.cms.RecipientInfo;
import iaik.pkcs.PKCSException;
import iaik.security.random.SecRandom;
import iaik.utils.Util;
import iaik.x509.X509Certificate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;

import demo.DemoUtil;
import demo.keystore.CMSKeyStore;


/**
 * Tests the IAIK CMS EnvelopedData(Stream) implementation against the
 * IAIK PKCS#7 EnvelopedData(Stream) implementation.
 * 
 * @author Dieter Bratko
 */
public class PKCS7CMSEnvelopedDataDemo {

  // certificate of user 1
  X509Certificate user1;
  // private key of user 1
  PrivateKey user1_pk;
  // certificate of user 2
  X509Certificate user2;
  // private key of user 2
  PrivateKey user2_pk;
  // secure random number generator
  SecureRandom random;

  /**
   * Setup the demo certificate chains.
   *
   * Keys and certificate are retrieved from the demo KeyStore.
   *
   * @exception IOException if an file read error occurs
   */
  public PKCS7CMSEnvelopedDataDemo() throws IOException {
    
    System.out.println();
    System.out.println("***********************************************************************************************");
    System.out.println("*                                 PKCS7CMSEnvelopedDataDemo                                   *");
    System.out.println("* (tests the CMS EnvelopedData against the IAIK-JCE PKCS#7 EnvelopedData type implementation) *");
    System.out.println("***********************************************************************************************");
    System.out.println();
    
    // add all certificates to the list
    X509Certificate[] certs = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT);
    user1 = certs[0];
    user1_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT);
    user2 = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_)[0];
    user2_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_);
  
    random = SecRandom.getDefault();

  }


  /**
   * Creates a CMS <code>EnvelopedDataStream</code> message.
   * <p>
   * The enveloped-data content type consists of encrypted content of any
   * type and encrypted content-encryption keys for one or more recipients.
   * The combination of encrypted content and encrypted content-encryption
   * key for a recipient is a "digital envelope" for that recipient. Any type
   * of content can be enveloped for any number of recipients in parallel.
   *
   * @param message the message to be enveloped, as byte representation
   * @return the DER encoding of the <code>EnvelopedData</code> object just created
   * @exception CMSException if the <code>EnvelopedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createEnvelopedDataStream(byte[] message) throws CMSException, IOException {

    EnvelopedDataStream enveloped_data;

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);
    // create a new EnvelopedData object encrypted with TripleDES CBC
    try {
      enveloped_data = new EnvelopedDataStream(is, (AlgorithmID)AlgorithmID.des_EDE3_CBC.clone());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("No implementation for Triple-DES-CBC.");
    }


    // create the recipient infos
    KeyTransRecipientInfo[] recipients = new KeyTransRecipientInfo[2];
    // user1 is the first receiver
    recipients[0] = new KeyTransRecipientInfo(user1, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // user2 is the second receiver
    recipients[1] = new KeyTransRecipientInfo(user2, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // specify the recipients of the encrypted message
    enveloped_data.setRecipientInfos(recipients);

    // return the EnvelopedDate as DER encoded byte array with block size 2048
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    enveloped_data.writeTo(os, 2048);
    return os.toByteArray();
  }

  /**
   * Decrypts the encrypted content of the given <code>EnvelopedData</code> object for the
   * specified recipient and returns the decrypted (= original) message.
   *
   * @param encoding the <code>EnvelopedData</code> object as DER encoded byte array
   * @param privateKey the private key to decrypt the message
   * @param recipientInfoIndex the index into the <code>RecipientInfo</code> array
   *                           to which the specified private key belongs
   *
   * @return the recovered message, as byte array
   * @exception CMSException if the message cannot be recovered
   * @exception IOException if an I/O error occurs
   */
  public byte[] getEnvelopedDataStream(byte[] encoding, PrivateKey privateKey, int recipientInfoIndex)
    throws CMSException, IOException {

    // create the EnvelopedData object from a DER encoded byte array
    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    EnvelopedDataStream enveloped_data = new EnvelopedDataStream(is);

    System.out.println("Information about the encrypted data:");
    EncryptedContentInfoStream eci = (EncryptedContentInfoStream)enveloped_data.getEncryptedContentInfo();
    System.out.println("Content type: "+eci.getContentType().getName());
    System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());

    System.out.println("\nThis message can be decrypted by the owners of the following certificates:");
    RecipientInfo[] recipients = enveloped_data.getRecipientInfos();
    for (int i=0; i<recipients.length; i++) {
      System.out.println("Recipient "+(i+1)+":");
      System.out.println(recipients[i].getRecipientIdentifiers()[0]);
    }

    // decrypt the message
    try {
      enveloped_data.setupCipher(privateKey, recipientInfoIndex);
      InputStream decrypted = enveloped_data.getInputStream();
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      Util.copyStream(decrypted, os, null);

      return os.toByteArray();

    } catch (InvalidKeyException ex) {
      throw new CMSException("Private key error: "+ex.toString());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.getMessage());
    }
  }


  /**
   * Creates a CMS <code>EnvelopedData</code> message.
   * <p>
   * The enveloped-data content type consists of encrypted content of any
   * type and encrypted content-encryption keys for one or more recipients.
   * The combination of encrypted content and encrypted content-encryption
   * key for a recipient is a "digital envelope" for that recipient. Any type
   * of content can be enveloped for any number of recipients in parallel.
   *
   * @param message the message to be enveloped, as byte representation
   * @return the <code>EnvelopedData</code> as ASN.1 object
   * @exception CMSException if the <code>EnvelopedData</code> object cannot
   *                          be created
   */
  public ASN1Object createEnvelopedData(byte[] message) throws CMSException {

    EnvelopedData enveloped_data;

    // create a new EnvelopedData object encrypted with TripleDES CBC
    try {
      enveloped_data = new EnvelopedData(message, (AlgorithmID)AlgorithmID.des_EDE3_CBC.clone());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("No implementation for Triple-DES-CBC.");
    }

  
    // create the recipient infos
    KeyTransRecipientInfo[] recipients = new KeyTransRecipientInfo[2];
    // user1 is the first receiver
    recipients[0] = new KeyTransRecipientInfo(user1, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // user2 is the second receiver
    recipients[1] = new KeyTransRecipientInfo(user2, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // specify the recipients of the encrypted message
    enveloped_data.setRecipientInfos(recipients);

    // return the EnvelopedDate as DER encoded byte array
    return enveloped_data.toASN1Object();
  }


  /**
   * Decrypts the encrypted content of the given <code>EnvelopedData</code> object for the
   * specified recipient and returns the decrypted (= original) message.
   *
   * @param obj the <code>EnvelopedData</code> as ASN.1 object
   * @param privateKey the private key to decrypt the message
   * @param recipientInfoIndex the index into the <code>RecipientInfo</code> array
   *                           to which the specified private key belongs
   *
   * @return the recovered message, as byte array
   * @exception CMSException if the message cannot be recovered
   */
  public byte[] getEnvelopedData(ASN1Object obj, PrivateKey privateKey, int recipientInfoIndex) 
    throws CMSException {

    EnvelopedData enveloped_data = new EnvelopedData(obj);

    System.out.println("Information about the encrypted data:");
    EncryptedContentInfo eci = (EncryptedContentInfo)enveloped_data.getEncryptedContentInfo();
    System.out.println("Content type: "+eci.getContentType().getName());
    System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());

    System.out.println("\nThis message can be decrypted by the owners of the following certificates:");
    RecipientInfo[] recipients = enveloped_data.getRecipientInfos();
    for (int i=0; i<recipients.length; i++) {
      System.out.println("Recipient "+(i+1)+":");
      System.out.println(recipients[i].getRecipientIdentifiers()[0]);
    }

    // decrypt the message
    try {
      enveloped_data.setupCipher(privateKey, recipientInfoIndex);
      return enveloped_data.getContent();

    } catch (InvalidKeyException ex) {
      throw new CMSException("Private key error: "+ex.toString());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.getMessage());
    }
  }
  
  // PKCS#7
  
  /**
   * Creates a PKCS#7 <code>EnvelopedDataStream</code> message.
   * <p>
   * The enveloped-data content type consists of encrypted content of any
   * type and encrypted content-encryption keys for one or more recipients.
   * The combination of encrypted content and encrypted content-encryption
   * key for a recipient is a "digital envelope" for that recipient. Any type
   * of content can be enveloped for any number of recipients in parallel.
   *
   * @param message the message to be enveloped, as byte representation
   * @return the DER encoding of the <code>EnvelopedData</code> object just created
   * @exception PKCSException if the <code>EnvelopedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createPKCS7EnvelopedDataStream(byte[] message) throws iaik.pkcs.PKCSException, IOException {

    iaik.pkcs.pkcs7.EnvelopedDataStream enveloped_data;

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);
    // create a new EnvelopedData object encrypted with TripleDES CBC
    try {
      enveloped_data = new iaik.pkcs.pkcs7.EnvelopedDataStream(is, (AlgorithmID)AlgorithmID.des_EDE3_CBC.clone());
    } catch (NoSuchAlgorithmException ex) {
      throw new iaik.pkcs.PKCSException("No implementation for Triple-DES-CBC.");
    }

    try {
      // create the recipient infos
      iaik.pkcs.pkcs7.RecipientInfo[] recipients = new iaik.pkcs.pkcs7.RecipientInfo[2];
      // user1 is the first receiver
      recipients[0] = new iaik.pkcs.pkcs7.RecipientInfo(user1, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
      // user2 is the second receiver
      recipients[1] = new iaik.pkcs.pkcs7.RecipientInfo(user2, (AlgorithmID)AlgorithmID.rsaEncryption.clone());

      // specify the recipients of the encrypted message
      enveloped_data.setRecipientInfos(recipients);
    } catch (NoSuchAlgorithmException ex) {
      throw new iaik.pkcs.PKCSException("Algorithm not supported: " + ex.toString());  
    }

    // return the EnvelopedDate as DER encoded byte array with block size 2048
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    enveloped_data.writeTo(os, 2048);
    return os.toByteArray();
  }

  /**
   * Decrypts the encrypted content of the given <code>EnvelopedData</code> object for the
   * specified recipient and returns the decrypted (= original) message.
   *
   * @param encoding the <code>EnvelopedData</code> object as DER encoded byte array
   * @param privateKey the private key to decrypt the message
   * @param recipientInfoIndex the index into the <code>RecipientInfo</code> array
   *                           to which the specified private key belongs
   *
   * @return the recovered message, as byte array
   * @exception PKCSException if the message cannot be recovered
   * @exception IOException if an I/O error occurs
   */
  public byte[] getPKCS7EnvelopedDataStream(byte[] encoding, PrivateKey privateKey, int recipientInfoIndex) throws iaik.pkcs.PKCSException, IOException {

    // create the EnvelopedData object from a DER encoded byte array
    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    iaik.pkcs.pkcs7.EnvelopedDataStream enveloped_data = new iaik.pkcs.pkcs7.EnvelopedDataStream(is);

    System.out.println("Information about the encrypted data:");
    iaik.pkcs.pkcs7.EncryptedContentInfoStream eci = (iaik.pkcs.pkcs7.EncryptedContentInfoStream)enveloped_data.getEncryptedContentInfo();
    System.out.println("Content type: "+eci.getContentType().getName());
    System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());

    System.out.println("\nThis message can be decrypted by the owners of the following certificates:");
    iaik.pkcs.pkcs7.RecipientInfo[] recipients = enveloped_data.getRecipientInfos();
    for (int i=0; i<recipients.length; i++) {
      System.out.println("Recipient "+(i+1)+":");
      System.out.println(recipients[i].getIssuerAndSerialNumber());
    }


    // decrypt the message
    try {
      enveloped_data.setupCipher(privateKey, recipientInfoIndex);
      InputStream decrypted = enveloped_data.getInputStream();
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      Util.copyStream(decrypted, os, null);

      return os.toByteArray();

    } catch (InvalidKeyException ex) {
      throw new iaik.pkcs.PKCSException("Private key error: "+ex.toString());
    } catch (NoSuchAlgorithmException ex) {
      throw new iaik.pkcs.PKCSException("Content encryption algorithm not implemented: "+ex.getMessage());
    }
  }


  /**
   * Creates a PKCS#7 <code>EnvelopedData</code> message.
   * <p>
   * The enveloped-data content type consists of encrypted content of any
   * type and encrypted content-encryption keys for one or more recipients.
   * The combination of encrypted content and encrypted content-encryption
   * key for a recipient is a "digital envelope" for that recipient. Any type
   * of content can be enveloped for any number of recipients in parallel.
   *
   * @param message the message to be enveloped, as byte representation
   * @return the <code>EnvelopedData</code> as ASN.1 object
   * @exception PKCSException if the <code>EnvelopedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public ASN1Object createPKCS7EnvelopedData(byte[] message) throws iaik.pkcs.PKCSException, IOException {

    iaik.pkcs.pkcs7.EnvelopedData enveloped_data;

    // create a new EnvelopedData object encrypted with TripleDES CBC
    try {
      enveloped_data = new iaik.pkcs.pkcs7.EnvelopedData(message, (AlgorithmID)AlgorithmID.des_EDE3_CBC.clone());
    } catch (NoSuchAlgorithmException ex) {
      throw new iaik.pkcs.PKCSException("No implementation for Triple-DES-CBC.");
    }

    try {
      // create the recipient infos
      iaik.pkcs.pkcs7.RecipientInfo[] recipients = new iaik.pkcs.pkcs7.RecipientInfo[2];
      // user1 is the first receiver
      recipients[0] = new iaik.pkcs.pkcs7.RecipientInfo(user1, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
      // user2 is the second receiver
      recipients[1] = new iaik.pkcs.pkcs7.RecipientInfo(user2, (AlgorithmID)AlgorithmID.rsaEncryption.clone());

      // specify the recipients of the encrypted message
      enveloped_data.setRecipientInfos(recipients);
    } catch (NoSuchAlgorithmException ex) {
      throw new iaik.pkcs.PKCSException("Algorithm not supported: " + ex.toString());
    }

    // return the EnvelopedDate as DER encoded byte array
    return enveloped_data.toASN1Object();
  }


  /**
   * Decrypts the encrypted content of the given <code>EnvelopedData</code> object for the
   * specified recipient and returns the decrypted (= original) message.
   *
   * @param obj the <code>EnvelopedData</code> as ASN.1 object
   * @param privateKey the private key to decrypt the message
   * @param recipientInfoIndex the index into the <code>RecipientInfo</code> array
   *                           to which the specified private key belongs
   *
   * @return the recovered message, as byte array
   * @exception PKCSException if the message cannot be recovered
   * @exception IOException if an I/O error occurs
   */
  public byte[] getPKCS7EnvelopedData(ASN1Object obj, PrivateKey privateKey, int recipientInfoIndex) throws iaik.pkcs.PKCSException, IOException {


    iaik.pkcs.pkcs7.EnvelopedData enveloped_data = new iaik.pkcs.pkcs7.EnvelopedData(obj);

    System.out.println("Information about the encrypted data:");
    iaik.pkcs.pkcs7.EncryptedContentInfo eci = (iaik.pkcs.pkcs7.EncryptedContentInfo)enveloped_data.getEncryptedContentInfo();
    System.out.println("Content type: "+eci.getContentType().getName());
    System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());

    System.out.println("\nThis message can be decrypted by the owners of the following certificates:");
    iaik.pkcs.pkcs7.RecipientInfo[] recipients = enveloped_data.getRecipientInfos();
    for (int i=0; i<recipients.length; i++) {
      System.out.println("Recipient "+(i+1)+":");
      System.out.println(recipients[i].getIssuerAndSerialNumber());
    }

    // decrypt the message
    try {
      enveloped_data.setupCipher(privateKey, recipientInfoIndex);
      return enveloped_data.getContent();

    } catch (InvalidKeyException ex) {
      throw new iaik.pkcs.PKCSException("Private key error: "+ex.toString());
    } catch (NoSuchAlgorithmException ex) {
      throw new iaik.pkcs.PKCSException("Content encryption algorithm not implemented: "+ex.getMessage());
    }
  }



  /**
   * Starts the test.
   */
  public void start() {
     // the test message
    String m = "This is the test message.";
    System.out.println("Test message: \""+m+"\"");
    System.out.println();
    byte[] message = m.getBytes();

    try {
      byte[] data;
      byte[] received_message = null;
      System.out.println("Stream implementation demos");
      System.out.println("===========================");


      // the stream implementation
      //
      // test CMS EnvelopedDataStream
      //
      System.out.println("\nCMS EnvelopedDataStream demo [create]:\n");
      data = createEnvelopedDataStream(message);
      // transmit data
      System.out.println("\nCMS EnvelopedDataStream demo [parse]:\n");
      // user1 means index 0 (hardcoded for this demo)
      received_message = getEnvelopedDataStream(data, user1_pk, 0);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(received_message));
      
      System.out.println("Testing compatibility to PKCS#7...");
      
      System.out.println("\nPKCS7 EnvelopedDataStream demo [create]:\n");
      data = createPKCS7EnvelopedDataStream(message);
      // transmit data
      System.out.println("\nCMS EnvelopedDataStream demo [parse]:\n");
      // user1 means index 0 (hardcoded for this demo)
      received_message = getEnvelopedDataStream(data, user1_pk, 0);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(received_message));
      
      System.out.println("\nPKCS7 EnvelopedDataStream demo [create]:\n");
      data = createPKCS7EnvelopedDataStream(message);
      // transmit data
      System.out.println("\nCMS EnvelopedDataStream demo [parse]:\n");
      // user1 means index 0 (hardcoded for this demo)
      received_message = getEnvelopedDataStream(data, user1_pk, 0);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(received_message));
      
      System.out.println("\nCMS EnvelopedDataStream demo [create]:\n");
      data = createEnvelopedDataStream(message);
      // transmit data
      System.out.println("\nPKCS7 EnvelopedDataStream demo [parse]:\n");
      // user1 means index 0 (hardcoded for this demo)
      received_message = getPKCS7EnvelopedDataStream(data, user1_pk, 0);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(received_message));




      // the non-stream implementation
      System.out.println("\nNon-stream implementation demos");
      System.out.println("===============================");

      ASN1Object obj = null;

      //
      // test CMS EnvelopedData
      //
      obj = null;
      System.out.println("\nCMS EnvelopedData demo [create]:\n");
      obj = createEnvelopedData(message);
      // transmit data
      System.out.println("\nCMS EnvelopedData demo [parse]:\n");
      // user1 means index 0 (hardcoded for this demo)
      received_message = getEnvelopedData(obj, user1_pk, 0);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(received_message));
      
      System.out.println("Testing compatibility to PKCS#7...");
      
      obj = null;
      System.out.println("\nPKCS7 EnvelopedData demo [create]:\n");
      obj = createPKCS7EnvelopedData(message);
      // transmit data
      System.out.println("\nCMS EnvelopedData demo [parse]:\n");
      // user1 means index 0 (hardcoded for this demo)
      received_message = getEnvelopedData(obj, user1_pk, 0);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(received_message));
      
      obj = null;
      System.out.println("\nCMS EnvelopedData demo [create]:\n");
      obj = createPKCS7EnvelopedData(message);
      // transmit data
      System.out.println("\nPKCS7 EnvelopedData demo [parse]:\n");
      // user1 means index 0 (hardcoded for this demo)
      received_message = getPKCS7EnvelopedData(obj, user1_pk, 0);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(received_message));


   	} catch (Exception ex) {
   	  ex.printStackTrace();
   	  throw new RuntimeException(ex.toString());
   	}
  }

  /**
   * The main method.
   *
   * @exception IOException
   *            if an I/O error occurs when reading required keys
   *            and certificates from files
   */
  public static void main(String argv[]) throws Exception {

   	DemoUtil.initDemos();

    (new PKCS7CMSEnvelopedDataDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
