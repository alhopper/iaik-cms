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
// $Header: /IAIK-CMS/current/src/demo/cms/ecc/ECDHEnvelopedDataDemo.java 17    23.08.13 14:20 Dbratko $
// $Revision: 17 $
//


package demo.cms.ecc;

import iaik.asn1.structures.AlgorithmID;
import iaik.cms.CMSAlgorithmID;
import iaik.cms.CMSException;
import iaik.cms.CertificateIdentifier;
import iaik.cms.ContentInfo;
import iaik.cms.ContentInfoStream;
import iaik.cms.EncryptedContentInfo;
import iaik.cms.EncryptedContentInfoStream;
import iaik.cms.EnvelopedData;
import iaik.cms.EnvelopedDataStream;
import iaik.cms.IssuerAndSerialNumber;
import iaik.cms.KeyAgreeRecipientInfo;
import iaik.cms.KeyIdentifier;
import iaik.cms.RecipientInfo;
import iaik.cms.RecipientKeyIdentifier;
import iaik.security.random.SecRandom;
import iaik.utils.Util;
import iaik.x509.X509Certificate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;

import javax.crypto.SecretKey;

import demo.DemoUtil;
import demo.cms.ecc.keystore.CMSEccKeyStore;

/**
 * Demonstrates the usage of class {@link iaik.cms.EnvelopedDataStream} and
 * {@link iaik.cms.EnvelopedData} for encrypting data using the CMS type
 * EnvelopedData by using Ephemeral-Static ECDH according to <a href = 
 * "http://www.ietf.org/rfc/rfc3278.txt" target="_blank">3278</a> as 
 * key agreement method.
 * <p>
 * Any keys/certificates required for this demo are read from a keystore
 * file "cmsecc.keystore" located in your current working directory. If
 * the keystore file does not exist you can create it by running the
 * {@link demo.cms.ecc.keystore.SetupCMSEccKeyStore SetupCMSEccKeyStore}
 * program. 
 * <br>
 * Additaionally to <code>iaik_cms.jar</code> you also must have 
 * <code>iaik_jce_(full).jar</code> (IAIK-JCE, <a href =
 * "http://jce.iaik.tugraz.at/sic/products/core_crypto_toolkits/jca_jce">
 * http://jce.iaik.tugraz.at/sic/products/core_crypto_toolkits/jca_jce</a>)
 * and <code>iaik_ecc.jar</code> (IAIK-ECC, <a href =
 * "http://jce.iaik.tugraz.at/sic/products/core_crypto_toolkits/ecc">
 * http://jce.iaik.tugraz.at/sic/products/core_crypto_toolkits/ecc</a>)
 * in your classpath.
 *
 * @see iaik.cms.EnvelopedDataStream
 * @see iaik.cms.EnvelopedData
 * @see iaik.cms.RecipientInfo
 * @see iaik.cms.KeyAgreeRecipientInfo
 * @see demo.cms.ecc.keystore.SetupCMSEccKeyStore
 * 
 * @author Dieter Bratko
 */
public class ECDHEnvelopedDataDemo {

  // certificate of ecdhUser 1
  X509Certificate ecdhUser1;
  // private key of ecdhUser 1
  PrivateKey ecdhUser1_pk;
  // certificate of ecdhUser 2
  X509Certificate ecdhUser2;
  // private key of ecdhUser 2
  PrivateKey ecdhUser2_pk;
  
  // secure random number generator
  SecureRandom random;

  /**
   * Setup the demo certificate chains.
   *
   * Keys and certificates are retrieved from the demo keyStore file
   * "cmsecc.keystore" located in your current working directory. If
   * the keystore file does not exist you can create it by running the
   * {@link demo.cms.ecc.keystore.SetupCMSEccKeyStore SetupCMSEccKeyStore}
   * program. 
   *
   * @exception IOException if keys/certificates cannot be read from the keystore
   */
  public ECDHEnvelopedDataDemo() throws IOException {
    
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                           ECDHEnvelopedData demo                               *");
    System.out.println("*   (shows the usage of the CMS EnvelopedData type implementation for ECDH)      *");
    System.out.println("**********************************************************************************");
    System.out.println();
    
    // add all certificates to the list
    
    ecdhUser1 = CMSEccKeyStore.getCertificateChain(CMSEccKeyStore.ECDH, CMSEccKeyStore.SZ_192_CRYPT)[0];
    ecdhUser1_pk = CMSEccKeyStore.getPrivateKey(CMSEccKeyStore.ECDH, CMSEccKeyStore.SZ_192_CRYPT);
    ecdhUser2 = CMSEccKeyStore.getCertificateChain(CMSEccKeyStore.ECDH, CMSEccKeyStore.SZ_192_CRYPT_)[0];
    ecdhUser2_pk = CMSEccKeyStore.getPrivateKey(CMSEccKeyStore.ECDH, CMSEccKeyStore.SZ_192_CRYPT_);
    
    random = SecRandom.getDefault();
    
  }

  /**
   * Creates a CMS <code>EnvelopedDataStream</code> message.
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
    RecipientInfo[] recipients = createRecipients();
    // specify the recipients of the encrypted message
    enveloped_data.setRecipientInfos(recipients);

    // return the EnvelopedDate as DER encoded byte array with block size 4
    // (just for testing; in real application we will use a proper blocksize,
    //  e.g. 2048, 4096,..)
    enveloped_data.setBlockSize(4);
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    ContentInfoStream cis = new ContentInfoStream(enveloped_data);
    cis.writeTo(os);
    return os.toByteArray();
  }

  /**
   * Decrypts the encrypted content of the given <code>EnvelopedData</code> object for
   * the recipient identified by its index into the recipientInfos field.
   *
   * @param encoding the <code>EnvelopedData</code> object as DER encoded byte array
   * @param key the key to decrypt the message
   * @param recipientInfoIndex the index into the <code>RecipientInfo</code> array
   *                           to which the specified key belongs
   *
   * @return the recovered message, as byte array
   * @exception CMSException if the message cannot be recovered
   * @exception IOException if a stream read/write error occurs
   */
  public byte[] getEnvelopedDataStream(byte[] encoding, Key key, int recipientInfoIndex)
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
    
    // for demonstration purposes we only look one time for all recipients included:
    if (recipientInfoIndex == 0) {
      int k = 0;
      for (int i=0; i<recipients.length; i++) {
        KeyIdentifier[] recipientIDs = recipients[i].getRecipientIdentifiers();
        for (int j = 0; j < recipientIDs.length; j++) {
          System.out.println("Recipient "+(++k)+":");
          System.out.println(recipientIDs[j]);
        }   
      }
    }
    // decrypt the message for the first recipient
    try {
      enveloped_data.setupCipher(key, recipientInfoIndex);
      InputStream decrypted = enveloped_data.getInputStream();
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      Util.copyStream(decrypted, os, null);

      return os.toByteArray();

    } catch (InvalidKeyException ex) {
      throw new CMSException("Private key error: "+ex.getMessage());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.getMessage());
    }
  }
  
  /**
   * Decrypts the encrypted content of the given <code>EnvelopedData</code> object for
   * the recipient identified by recipient identifier.
   *
   * @param encoding the <code>EnvelopedData</code> object as DER encoded byte array
   * @param key the key to decrypt the message
   * @param recipientID the recipient identifier uniquely identifying the key of the
   *        recipient
   *
   * @return the recovered message, as byte array
   * @exception CMSException if the message cannot be recovered
   * @exception IOException if a stream read/write error occurs
   */
  public byte[] getEnvelopedDataStream(byte[] encoding, Key key, KeyIdentifier recipientID)
    throws CMSException, IOException {

    // create the EnvelopedData object from a DER encoded byte array
    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    EnvelopedDataStream enveloped_data = new EnvelopedDataStream(is);

    System.out.println("Information about the encrypted data:");
    EncryptedContentInfoStream eci = (EncryptedContentInfoStream)enveloped_data.getEncryptedContentInfo();
    System.out.println("Content type: "+eci.getContentType().getName());
    System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());
    
    // get the right RecipientInfo
    System.out.println("\nSearch for RecipientInfo:");
    RecipientInfo recipient = enveloped_data.getRecipientInfo(recipientID);
    if (recipient != null) {
      System.out.println("RecipientInfo: " + recipient);   
    } else {
      throw new CMSException("No recipient with ID: " + recipientID);
    }    
    // decrypt the content encryption key and the content
    try {
      System.out.println("Decrypt encrypted content encryption key...");
      SecretKey cek = recipient.decryptKey(key, recipientID);
      System.out.println("Decrypt content with decrypted content encryption key...");
      enveloped_data.setupCipher(cek);
      InputStream decrypted = enveloped_data.getInputStream();
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      Util.copyStream(decrypted, os, null);

      return os.toByteArray();

    } catch (InvalidKeyException ex) {
      throw new CMSException("Private key error: "+ex.getMessage());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.getMessage());
    }
  }
  
  // non stream

  /**
   * Creates a CMS <code>EnvelopedData</code> message.
   * 
   * @param message the message to be enveloped, as byte representation
   * 
   * @return the encoded <code>EnvelopedData</code>, as byte array
   * 
   * @exception CMSException if the <code>EnvelopedData</code> object cannot
   *                          be created
   */
  public byte[] createEnvelopedData(byte[] message) throws CMSException {
    
    EnvelopedData enveloped_data;

    // create a new EnvelopedData object encrypted with TripleDES CBC
    try {
      enveloped_data = new EnvelopedData(message, (AlgorithmID)AlgorithmID.des_EDE3_CBC.clone());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("No implementation for Triple-DES-CBC.");
    }
    
    // set the RecipientInfos
    RecipientInfo[] recipients = createRecipients();
    enveloped_data.setRecipientInfos(recipients);

    // return encoded EnvelopedData
    // wrap into contentInfo
    ContentInfo ci = new ContentInfo(enveloped_data);
    return ci.getEncoded();
  }


  /**
   * Decrypts the encrypted content of the given <code>EnvelopedData</code> object for
   * the recipient identified by its index into the recipientInfos field.
   *
   * @param enc the encoded <code>EnvelopedData</code>
   * @param key the key to decrypt the message
   * @param recipientInfoIndex the index into the <code>RecipientInfo</code> array
   *                           to which the specified key belongs
   *
   * @return the recovered message, as byte array
   * 
   * @exception CMSException if the message cannot be recovered
   * @exception IOException if an I/O error occurs
   */
  public byte[] getEnvelopedData(byte[] enc, Key key, int recipientInfoIndex) 
    throws CMSException, IOException {
    ByteArrayInputStream bais = new ByteArrayInputStream(enc);
    EnvelopedData enveloped_data = new EnvelopedData(bais);

    System.out.println("Information about the encrypted data:");
    EncryptedContentInfo eci = (EncryptedContentInfo)enveloped_data.getEncryptedContentInfo();
    System.out.println("Content type: "+eci.getContentType().getName());
    System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());

    System.out.println("\nThis message can be decrypted by the owners of the following certificates:");
    RecipientInfo[] recipients = enveloped_data.getRecipientInfos();
    
    // for demonstration purposes we only look one time for all recipients included:
    if (recipientInfoIndex == 0) {
      int k = 0;
      for (int i=0; i<recipients.length; i++) {
        KeyIdentifier[] recipientIDs = recipients[i].getRecipientIdentifiers();
        for (int j = 0; j < recipientIDs.length; j++) {
          System.out.println("Recipient "+(++k)+":");
          System.out.println(recipientIDs[j]);
        }   
      }
    }
    
    // decrypt the message
    try {
      enveloped_data.setupCipher(key, recipientInfoIndex);
      return enveloped_data.getContent();

    } catch (InvalidKeyException ex) {
      throw new CMSException("Private key error: "+ex.getMessage());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.getMessage());
    }
  }
  
  /**
   * Decrypts the encrypted content of the given <code>EnvelopedData</code> object for
   * the recipient identified by recipient identifier.
   * <p>
   * This way of decrypting the content may be used for any type of RecipientInfo
   * (KeyTransRecipientInfo, KeyAgreeRecipientInfo, KEKRecipientInfo). The 
   * recipient in mind is identified by its recipient identifier.
   *
   * @param enc the encoded <code>AuthenticatedData</code>
   * @param key the key to decrypt the message
   * @param recipientID the recipient identifier uniquely identifying the key of the
   *        recipient
   *
   * @return the recovered message, as byte array
   * @exception CMSException if the message cannot be recovered
   * @exception IOException if an I/O error occurs
   */
  public byte[] getEnvelopedData(byte[] enc, Key key, KeyIdentifier recipientID) 
    throws CMSException, IOException {
    ByteArrayInputStream bais = new ByteArrayInputStream(enc);
    EnvelopedData enveloped_data = new EnvelopedData(bais);

    System.out.println("Information about the encrypted data:");
    EncryptedContentInfo eci = (EncryptedContentInfo)enveloped_data.getEncryptedContentInfo();
    System.out.println("Content type: "+eci.getContentType().getName());
    System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());

    System.out.println("\nThis message can be decrypted by the owners of the following certificates:");

    // get the right RecipientInfo
    System.out.println("\nSearch for RecipientInfo:");
    RecipientInfo recipient = enveloped_data.getRecipientInfo(recipientID);
    if (recipient != null) {
      System.out.println("RecipientInfo: " + recipient);   
    } else {
      throw new CMSException("No recipient with ID: " + recipientID);
    }    
    // decrypt the content encryption key and the content
    try {
      System.out.println("Decrypt encrypted content encryption key...");
      SecretKey cek = recipient.decryptKey(key, recipientID);
      System.out.println("Decrypt content with decrypted content encryption key...");
      enveloped_data.setupCipher(cek);
      return enveloped_data.getContent();

    } catch (InvalidKeyException ex) {
      throw new CMSException("Private key error: "+ex.getMessage());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.getMessage());
    }
  }
  
  /**
   * Decrypts the encrypted content of the given <code>EnvelopedData</code> object for
   * the recipient identified by its recipient certificate.
   *
   * @param enc the encoded <code>EnvelopedData</code>
   * @param key the key to decrypt the message
   * @param recipientCert the certificate of the recipient 
   *
   * @return the recovered message, as byte array
   *
   * @exception CMSException if the message cannot be recovered
   */
  public byte[] getEnvelopedData(byte[] enc, Key key, X509Certificate recipientCert) 
    throws CMSException, IOException {
    ByteArrayInputStream bais = new ByteArrayInputStream(enc);
    EnvelopedData enveloped_data = new EnvelopedData(bais);

    System.out.println("Information about the encrypted data:");
    EncryptedContentInfo eci = (EncryptedContentInfo)enveloped_data.getEncryptedContentInfo();
    System.out.println("Content type: "+eci.getContentType().getName());
    System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());

    System.out.println("\nThis message can be decrypted by the owners of the following certificates:");

    // decrypt the content encryption key and the content
    try {
      System.out.println("Decrypt the content...");
      enveloped_data.setupCipher(key, recipientCert);
      return enveloped_data.getContent();

    } catch (InvalidKeyException ex) {
      throw new CMSException("Private key error: "+ex.getMessage());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.getMessage());
    }
  }
  
  /**
   * Creates the RecipientInfos.
   *
   * @return the RecipientInfos created, two KeyAgreeRecipientInfos
   *
   * @exception CMSException if an error occurs when creating the recipient infos
   */
  public RecipientInfo[] createRecipients() throws CMSException {
    
    RecipientInfo[] recipients = new RecipientInfo[2];
    try {
      // recipients use key agreement
      // the key encryption (key agreement) algorithm to use:
      AlgorithmID keyEA1 = (AlgorithmID)CMSAlgorithmID.dhSinglePass_stdDH_sha1kdf_scheme.clone();
      // the key wrap algorithm to use:
      AlgorithmID keyWrapAlg1 = (AlgorithmID)AlgorithmID.cms_3DES_wrap.clone();
      // the length of the key encryption key to be generated:
      int kekLength1 = 192;
      recipients[0] = new KeyAgreeRecipientInfo(keyEA1, keyWrapAlg1, kekLength1);
      // ecdhUser1 is the first receiver  (cert identified by IssuerAndSerialNumber)
      ((KeyAgreeRecipientInfo)recipients[0]).addRecipient(ecdhUser1, CertificateIdentifier.ISSUER_AND_SERIALNUMBER);
  
      // ecdhUser2 is the second receiver (cert identified by RecipientKeyIdentifier)
      // the key encryption (key agreement) algorithm to use:
      AlgorithmID keyEA2 = (AlgorithmID)CMSAlgorithmID.dhSinglePass_cofactorDH_sha1kdf_scheme.clone();
      // the key wrap algorithm to use:
      AlgorithmID keyWrapAlg2 = (AlgorithmID)AlgorithmID.cms_3DES_wrap.clone();
      // the length of the key encryption key to be generated:
      int kekLength2 = 192;
      recipients[1] = new KeyAgreeRecipientInfo(keyEA2, keyWrapAlg2, kekLength2);
      // ecdhUser1 is the first receiver  (cert identified by RecipientKeyIdentifier)
      ((KeyAgreeRecipientInfo)recipients[1]).addRecipient(ecdhUser2, CertificateIdentifier.RECIPIENT_KEY_IDENTIFIER);
      
    } catch (Exception ex) {
      throw new CMSException("Error adding recipients: " + ex.toString()); 
    }    
    return recipients;
  }  
  
  /**
   * Parses an EnvelopedData and decrypts the content for all test recipients
   * using the index into the recipientInfos field for identifying the recipient.
   *
   * @param stream whether to use EnvelopedDataStream or EnvelopedData
   * @param encodedEnvelopedData the encoded EnvelopedData object 
   *
   * @exception Exception if some error occurs during decoding/decryption
   */ 
  public void parseEnvelopedDataWithRecipientInfoIndex(boolean stream, byte[] encodedEnvelopedData) throws Exception {
    byte[] receivedMessage;
    if (stream) {
      // ecdhUser1
      System.out.println("\nDecrypt for ecdhUser1:");
      receivedMessage = getEnvelopedDataStream(encodedEnvelopedData, ecdhUser1_pk, 0);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // ecdhUser2
      System.out.println("\nDecrypt for ecdhUser2:");
      receivedMessage = getEnvelopedDataStream(encodedEnvelopedData, ecdhUser2_pk, 1);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
    } else {
      // ecdhUser1
      System.out.println("\nDecrypt for ecdhUser1:");
      receivedMessage = getEnvelopedData(encodedEnvelopedData, ecdhUser1_pk, 0);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // ecdhUser2
      System.out.println("\nDecrypt for ecdhUser2:");
      receivedMessage = getEnvelopedData(encodedEnvelopedData, ecdhUser2_pk, 1);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
    }    
  }
  
  /**
   * Parses an EnvelopedData and decrypts the content for all test recipients
   * using their recipient identifiers for identifying the recipient.
   *
   * @param stream whether to use EnvelopedDataStream or EnvelopedData
   * @param encodedEnvelopedData the encoded EnvelopedData object 
   *
   * @exception Exception if some error occurs during decoding/decryption
   */ 
  public void parseEnvelopedDataWithRecipientIdentifier(boolean stream, byte[] encodedEnvelopedData) throws Exception {
    byte[] receivedMessage;
    if (stream) {
      // ecdhUser1
      System.out.println("\nDecrypt for ecdhUser1:");
      receivedMessage = getEnvelopedDataStream(encodedEnvelopedData, ecdhUser1_pk, new IssuerAndSerialNumber(ecdhUser1));
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // ecdhUser2
      System.out.println("\nDecrypt for ecdhUser2:");
      receivedMessage = getEnvelopedDataStream(encodedEnvelopedData, ecdhUser2_pk, new RecipientKeyIdentifier(ecdhUser2));
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
    } else {
      // ecdhUser1
      System.out.println("\nDecrypt for ecdhUser1:");
      receivedMessage = getEnvelopedData(encodedEnvelopedData, ecdhUser1_pk, new IssuerAndSerialNumber(ecdhUser1));
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // ecdhUser2
      System.out.println("\nDecrypt for ecdhUser2:");
      receivedMessage = getEnvelopedData(encodedEnvelopedData, ecdhUser2_pk, new RecipientKeyIdentifier(ecdhUser2));
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
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
      byte[] encoding;
      System.out.println("Stream implementation demos");
      System.out.println("===========================");


      // the stream implementation
      //
      // test CMS EnvelopedDataStream
      //
      System.out.println("\nCMS EnvelopedDataStream demo [create]:\n");
      encoding = createEnvelopedDataStream(message);
      // transmit data
      System.out.println("\nCMS EnvelopedDataStream demo [parse]:\n");
      System.out.println("Decrypt for the several recipients using their index into the recipientInfos field.");
      parseEnvelopedDataWithRecipientInfoIndex(true, encoding);
      System.out.println("Decrypt for the several recipients using their RecipientIdentifier.");
      parseEnvelopedDataWithRecipientIdentifier(true, encoding);
      
      // the non-stream implementation
      System.out.println("\nNon-stream implementation demos");
      System.out.println("===============================");

            
      //
      // test CMS EnvelopedData
      //
      System.out.println("\nCMS EnvelopedData demo [create]:\n");
      encoding = createEnvelopedData(message);
      // transmit data
      System.out.println("\nCMS EnvelopedData demo [parse]:\n");
      System.out.println("Decrypt for the several recipients using their index into the recipientInfos field.");
      parseEnvelopedDataWithRecipientInfoIndex(false, encoding);
      System.out.println("Decrypt for the several recipients using their RecipientIdentifier.");
      parseEnvelopedDataWithRecipientIdentifier(false, encoding);
      
      

   	} catch (Exception ex) {
   	  ex.printStackTrace();
   	  throw new RuntimeException(ex.toString());
   	}
  }
  
  /**
   * Main method.
   *
   * @exception IOException
   *            if an I/O error occurs when reading required keys
   *            and certificates from the keystore file
   */
  public static void main(String argv[]) throws Exception {

   	DemoUtil.initDemos();
    ECCDemoUtil.installIaikEccProvider();
    (new ECDHEnvelopedDataDemo()).start();
    System.out.println("\nReady!");
    System.in.read();
  }
}
