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
// $Header: /IAIK-CMS/current/src/demo/cms/envelopedData/EnvelopedDataDemo.java 35    23.08.13 14:22 Dbratko $
// $Revision: 35 $
//


package demo.cms.envelopedData;

import iaik.asn1.structures.AlgorithmID;
import iaik.cms.CMSException;
import iaik.cms.CertificateIdentifier;
import iaik.cms.EncryptedContentInfo;
import iaik.cms.EncryptedContentInfoStream;
import iaik.cms.EnvelopedData;
import iaik.cms.EnvelopedDataStream;
import iaik.cms.IssuerAndSerialNumber;
import iaik.cms.KEKIdentifier;
import iaik.cms.KEKRecipientInfo;
import iaik.cms.KeyAgreeRecipientInfo;
import iaik.cms.KeyIdentifier;
import iaik.cms.KeyTransRecipientInfo;
import iaik.cms.RecipientInfo;
import iaik.cms.RecipientKeyIdentifier;
import iaik.cms.SubjectKeyID;
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
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import demo.DemoUtil;
import demo.keystore.CMSKeyStore;


/**
 * Demonstrates the usage of class {@link iaik.cms.EnvelopedDataStream} and
 * {@link iaik.cms.EnvelopedData} for encrypting data using the CMS type
 * EnvelopedData.
 * <p>
 * This demo creates an EnvelopedData object and subsequently shows several
 * ways that may be used for decrypting the content for some particular 
 * recipient.
 * <p>
 * Keys and certificates are retrieved from the demo KeyStore ("cms.keystore") 
 * which has to be located in your current working directory and may be
 * created by running the {@link demo.keystore.SetupCMSKeyStore
 * SetupCMSKeyStore} program.
 * 
 * @see iaik.cms.EnvelopedDataStream
 * @see iaik.cms.EnvelopedData
 * @see iaik.cms.RecipientInfo
 * @see iaik.cms.KeyTransRecipientInfo
 * @see iaik.cms.KeyAgreeRecipientInfo
 * @see iaik.cms.KEKRecipientInfo
 * 
 * @author Dieter Bratko
 */
public class EnvelopedDataDemo {

  // certificate of rsaUser 1
  X509Certificate rsaUser1_;
  // private key of rsaUser 1
  PrivateKey rsaUser1Pk_;
  // certificate of rsaUser 2
  X509Certificate rsaUser2_;
  // private key of rsaUser 2
  PrivateKey rsaUser2Pk_;

  // certificate of esdhUser 1
  X509Certificate esdhUser1_;
  // private key of esdhUser 1
  PrivateKey esdhUser1Pk_;
  // certificate of esdhUser 2
  X509Certificate esdhUser2_;
  // private key of esdhUser 2
  PrivateKey esdhUser2Pk_;
  
  // key encryption key for KEKRecipientInfo
  SecretKey kek_;
  byte[] kekID_;
  
  // content encryption algorithm to be used
  AlgorithmID contentEncAlg_;
  // cek algorithm
  String cekAlg_;
  // key wrap algorithm to be used
  AlgorithmID keyWrapAlg_;
  // key length (same for content encryption key and key encryption key
  int keyLength_;

  // secure random number generator
  SecureRandom random_;
  
  /**
   * Creates an EnvelopedDataDemo and setups the demo certificates.
   * <br>
   * Keys and certificates are retrieved from the demo KeyStore ("cms.keystore")
   * file which has to be located in your current working directory and may be
   * created by running {@link demo.keystore.SetupCMSKeyStore
   * SetupCMSKeyStore}.
   * <br>
   * TripleDES and TripleDES KeyWrap are used for content encryption and
   * content encryption key wrapping.
   *
   * @exception IOException if an file read error occurs
   * @exception NoSuchAlgorithmException if the requested TripleDES or TripleDES KeyWrap 
   *                                     algorithms are not supported
   */
  public EnvelopedDataDemo() throws IOException, NoSuchAlgorithmException {
    this((AlgorithmID)AlgorithmID.des_EDE3_CBC.clone(),
         (AlgorithmID)AlgorithmID.cms_3DES_wrap.clone(),
         "3DES",
         192);
  }
  
  /**
   * Creates an EnvelopedDataDemo and setups the demo certificates.
   * <br>
   * Keys and certificates are retrieved from the demo KeyStore ("cms.keystore")
   * file which has to be located in your current working directory and may be
   * created by running {@link demo.keystore.SetupCMSKeyStore
   * SetupCMSKeyStore}.
   *
   * @param contentEncAlg the content encryption algorithm to be used
   * @param keyWrapAlg the key wrap algorithm to be used for wrapping the content 
   *                   encryption key (for KeyAgreeRecipientInfos)
   * @param keyLength the key length to be used (same for content encryption key
   *                  and key encryption key) (for KeyAgreeRecipientInfos and
   *                  KEKRecipientInfos)
   *                                    
   * @exception IOException if an file read error occurs
   * @exception NoSuchAlgorithmException if the requested algorithms are not supported
   */
  public EnvelopedDataDemo(AlgorithmID contentEncAlg,
                           AlgorithmID keyWrapAlg,
                           int keyLength) throws IOException, NoSuchAlgorithmException {
    this(contentEncAlg, keyWrapAlg, keyWrapAlg.getImplementationName(), keyLength);
    
  }
      

  /**
   * Creates an EnvelopedDataDemo and setups the demo certificates.
   * <br>
   * Keys and certificates are retrieved from the demo KeyStore ("cms.keystore")
   * file which has to be located in your current working directory and may be
   * created by running {@link demo.keystore.SetupCMSKeyStore
   * SetupCMSKeyStore}.
   *
   * @param contentEncAlg the content encryption algorithm to be used
   * @param keyWrapAlg the key wrap algorithm to be used for wrapping the content 
   *                   encryption key (for KeyAgreeRecipientInfos)
   * @param kekAlg the name of the key encryption key algorithm to be used
   *               (for KEKRecipientInfos)
   * @param keyLength the key length to be used (same for content encryption key
   *                  and key encryption key) (for KeyAgreeRecipientInfos and
   *                  KEKRecipientInfos)
   *                                    
   * @exception IOException if an file read error occurs
   * @exception NoSuchAlgorithmException if the requested algorithms are not supported
   */
  public EnvelopedDataDemo(AlgorithmID contentEncAlg,
                           AlgorithmID keyWrapAlg,
                           String kekAlg,
                           int keyLength) throws IOException, NoSuchAlgorithmException {
    
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("                  EnvelopedDataDemo " + contentEncAlg.getName());
    System.out.println("        (shows the usage of the CMS EnvelopedData type implementation)          ");
    System.out.println("**********************************************************************************");
    System.out.println();
    
    // add all certificates to the list
    X509Certificate[] certs = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT);
    rsaUser1_ = certs[0];
    rsaUser1Pk_ = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT);
    rsaUser2_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_)[0];
    rsaUser2Pk_ = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_);
    
    esdhUser1_ = CMSKeyStore.getCertificateChain(CMSKeyStore.ESDH, CMSKeyStore.SZ_1024_CRYPT)[0];
    esdhUser1Pk_ = CMSKeyStore.getPrivateKey(CMSKeyStore.ESDH, CMSKeyStore.SZ_1024_CRYPT);
    esdhUser2_ = CMSKeyStore.getCertificateChain(CMSKeyStore.ESDH, CMSKeyStore.SZ_1024_CRYPT_)[0];
    esdhUser2Pk_ = CMSKeyStore.getPrivateKey(CMSKeyStore.ESDH, CMSKeyStore.SZ_1024_CRYPT_);
    random_ = SecRandom.getDefault();
    
    contentEncAlg_ = contentEncAlg;
    keyWrapAlg_ = keyWrapAlg;
    keyLength_ = keyLength;
    
    
    // create a secret key encryption key for a KEKRecipientInfo
    KeyGenerator kg;
    try {
      kg = KeyGenerator.getInstance(kekAlg, "IAIK");
    } catch (NoSuchProviderException ex) {
      throw new IOException("Provider IAIK not available: " + ex.toString());   
    }   
    kg.init(keyLength_, random_);
    kek_ = kg.generateKey();
    kekID_ = new byte[] { 00, 00, 00, 01 };
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
      enveloped_data = new EnvelopedDataStream(is, (AlgorithmID)contentEncAlg_.clone());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("No implementation for content encryption algorithm: " + ex.toString());
    }

    // create the recipient infos
    RecipientInfo[] recipients = createRecipients();
    // specify the recipients of the encrypted message
    enveloped_data.setRecipientInfos(recipients);

    // return the EnvelopedDate as DER encoded byte array with block size 2048
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    enveloped_data.writeTo(os, 2048);
    return os.toByteArray();
  }

  /**
   * Decrypts the encrypted content of the given <code>EnvelopedData</code> object for
   * the recipient identified by its index into the recipientInfos field.
   * <p>
   * This way of decrypting the content may be used for any type of RecipientInfo
   * (KeyTransRecipientInfo, KeyAgreeRecipientInfo, KEKRecipientInfo), but requires to
   * know at what index of the recipientInfo field the RecipientInfo for the 
   * particular recipient in mind can be found. If the recipient in mind uses
   * a RecipientInfo of type KeyAgreeRecipientInfo some processing overhead may
   * take place because a KeyAgreeRecipientInfo may contain encrypted content-encryption
   * keys for more than only one recipient; since the recipientInfoIndex only
   * specifies the RecipientInfo but not the encrypted content encryption key 
   * -- if there are more than only one -- repeated decryption runs may be
   * required as long as the decryption process completes successfully.
   *
   * @param encoding the <code>EnvelopedData</code> object as DER encoded byte array
   * @param key the key to decrypt the message
   * @param recipientInfoIndex the index into the <code>RecipientInfo</code> array
   *                        to which the specified key belongs
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
   * <p>
   * This way of decrypting the content may be used for any type of RecipientInfo
   * (KeyTransRecipientInfo, KeyAgreeRecipientInfo, KEKRecipientInfo). The 
   * recipient in mind is identified by its recipient identifier.
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
  
  /**
   * Decrypts the encrypted content of the given <code>EnvelopedData</code> object for
   * the recipient identified by its recipient certificate or kekID.
   * <p>
   * Since recipient certificates only may be used for for RecipientInfos of type
   * KeyTransRecipientInfo or KeyAgreeRecipientInfo, a key id has to be supplied
   * for decrypting the content for a recipient using a KEKRecipientInfo.
   *
   * @param encoding the <code>EnvelopedData</code> object as DER encoded byte array
   * @param key the key to decrypt the message
   * @param recipientCert the certificate of the recipient having a RecipientInfo of
   *                      type KeyTransRecipientInfo or KeyAgreeRecipientInfo
   * @param kekID the kekID identifying the recipient key when using a RecipientInfo
   *              of type KEKRecipientInfo
   *
   * @return the recovered message, as byte array
   * @exception CMSException if the message cannot be recovered
   * @exception IOException if a stream read/write error occurs
   */
  public byte[] getEnvelopedDataStream(byte[] encoding, Key key, X509Certificate recipientCert, byte[] kekID)
    throws CMSException, IOException {

    // create the EnvelopedData object from a DER encoded byte array
    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    EnvelopedDataStream enveloped_data = new EnvelopedDataStream(is);

    System.out.println("Information about the encrypted data:");
    EncryptedContentInfoStream eci = (EncryptedContentInfoStream)enveloped_data.getEncryptedContentInfo();
    System.out.println("Content type: "+eci.getContentType().getName());
    System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());
    
    // decrypt the content encryption key and the content
    try {
      System.out.println("Decrypt the content...");
      if (recipientCert != null) {
        enveloped_data.setupCipher(key, recipientCert);
      } else {
        // KEKRecipientInfo
        enveloped_data.setupCipher(key, new KEKIdentifier(kekID));
      }  
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
      enveloped_data = new EnvelopedData(message, (AlgorithmID)contentEncAlg_.clone());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("No implementation for content encryption algorithm: " + ex.toString());
    }
    
    // set the RecipientInfos
    RecipientInfo[] recipients = createRecipients();
    enveloped_data.setRecipientInfos(recipients);

    // return encoded EnvelopedData
    return enveloped_data.getEncoded();
  }


  /**
   * Decrypts the encrypted content of the given <code>EnvelopedData</code> object for
   * the recipient identified by its index into the recipientInfos field.
   * <p>
   * This way of decrypting the content may be used for any type of RecipientInfo
   * (KeyTransRecipientInfo, KeyAgreeRecipientInfo, KEKRecipientInfo), but requires to
   * know at what index of the recipientInfo field the RecipientInfo for the 
   * particular recipient in mind can be found. If the recipient in mind uses
   * a RecipientInfo of type KeyAgreeRecipientInfo some processing overhead may
   * take place because a KeyAgreeRecipientInfo may contain encrypted content-encryption
   * keys for more than only one recipient; since the recipientInfoIndex only
   * specifies the RecipientInfo but not the encrypted content encryption key 
   * -- if there are more than only one -- repeated decryption runs may be
   * required as long as the decryption process completes successfully.
   *
   * @param enc the encoded <code>EnvelopedData</code>
   * 
   * @param key the key to decrypt the message
   * 
   * @param recipientInfoIndex the index into the <code>RecipientInfo</code> array
   *                    to which the specified key belongs
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
   * @param enc the DER encoded <code>EnvelopedData</code> ASN.1 object
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
   * the recipient identified by its recipient certificate or keyID.
   * <p>
   * Since recipient certificates only may be used for for RecipientInfos of type
   * KeyTransRecipientInfo or KeyAgreeRecipientInfo, a key id has to be supplied
   * for decrypting the content for a recipient using a KEKRecipientInfo.
   *
   * @param enc the DER encoded <code>EnvelopedData</code> ASN.1 object
   * @param key the key to decrypt the message
   * @param recipientCert the certificate of the recipient having a RecipientInfo of
   *                      type KeyTransRecipientInfo or KeyAgreeRecipientInfo
   * @param kekID the kekID identifying the recipient key when using a RecipientInfo
   *              of type KEKRecipientInfo
   *
   * @return the recovered message, as byte array
   * @exception CMSException if the message cannot be recovered
   */
  public byte[] getEnvelopedData(byte[] enc, Key key, X509Certificate recipientCert, byte[] kekID) 
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
      if (recipientCert != null) {
        enveloped_data.setupCipher(key, recipientCert);
      } else {
        // KEKRecipientInfo
        enveloped_data.setupCipher(key, new KEKIdentifier(kekID));
      }  
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
   * @return the RecipientInfos created, two KeyTransRecipientInfos, one
   *         KeyAgreeRecipientInfo (for two recipients with same domain
   *         parameters), and one KEKRecipientInfo
   *
   * @exception CMSException if an error occurs when creating the recipient infos
   */
  public RecipientInfo[] createRecipients() throws CMSException {
    
    RecipientInfo[] recipients = new RecipientInfo[4];
    try {
      // rsaUser1 is the first receiver (cert identified by IssuerAndSerialNumber)
      recipients[0] = new KeyTransRecipientInfo(rsaUser1_, 
                                                (AlgorithmID)AlgorithmID.rsaEncryption.clone());
      // rsaUser2 is the second receiver (cert identifief by SubjectKeyIdentifier)
      recipients[1] = new KeyTransRecipientInfo(rsaUser2_, 
                                                CertificateIdentifier.SUBJECT_KEY_IDENTIFIER, 
                                                (AlgorithmID)AlgorithmID.rsaEncryption.clone());

      // next recipients use key agreement
      // the key encryption (key agreement) algorithm to use:
      AlgorithmID keyEA = (AlgorithmID)AlgorithmID.esdhKeyAgreement.clone();
      // the key wrap algorithm to use:
      AlgorithmID keyWrapAlg = (AlgorithmID)keyWrapAlg_.clone();
      // the length of the key encryption key to be generated:
      int kekLength = keyLength_;
      recipients[2] = new KeyAgreeRecipientInfo(keyEA, keyWrapAlg, kekLength);
      // esdhUser1 is the third receiver  (cert identified by IssuerAndSerialNumber)
      ((KeyAgreeRecipientInfo)recipients[2]).addRecipient(esdhUser1_, CertificateIdentifier.ISSUER_AND_SERIALNUMBER);
      // esdhUser2 is the fourth receiver (cert identified by RecipientKeyIdentifier)
      ((KeyAgreeRecipientInfo)recipients[2]).addRecipient(esdhUser2_, CertificateIdentifier.RECIPIENT_KEY_IDENTIFIER);
      
      // last receiver uses a symmetric key encryption key  
      AlgorithmID kea = (AlgorithmID)keyWrapAlg_.clone();
      KEKIdentifier kekIdentifier = new KEKIdentifier(kekID_);
      recipients[3] = new KEKRecipientInfo(kekIdentifier, kea, kek_);
    } catch (Exception ex) {
      throw new CMSException("Error adding recipients: " + ex.getMessage()); 
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
      // rsaUser1
      System.out.println("\nDecrypt for rsaUser1:");
      receivedMessage = getEnvelopedDataStream(encodedEnvelopedData, rsaUser1Pk_, 0);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // rsaUser2
      System.out.println("\nDecrypt for rsaUser2:");
      receivedMessage = getEnvelopedDataStream(encodedEnvelopedData, rsaUser2Pk_, 1);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // esdhUser1
      System.out.println("\nDecrypt for esdhUser1:");
      receivedMessage = getEnvelopedDataStream(encodedEnvelopedData, esdhUser1Pk_, 2);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // esdhUser2
      System.out.println("\nDecrypt for esdhUser2:");
      receivedMessage = getEnvelopedDataStream(encodedEnvelopedData, esdhUser2Pk_, 2);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // kekUser
      System.out.println("\nDecrypt for kekUser:");
      receivedMessage = getEnvelopedDataStream(encodedEnvelopedData, kek_, 3);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
    } else {
      // rsaUser1
      System.out.println("\nDecrypt for rsaUser1:");
      receivedMessage = getEnvelopedData(encodedEnvelopedData, rsaUser1Pk_, 0);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
       // rsaUser2
      System.out.println("\nDecrypt for rsaUser2:");
      receivedMessage = getEnvelopedData(encodedEnvelopedData, rsaUser2Pk_, 1);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // esdhUser1
      System.out.println("\nDecrypt for esdhUser1:");
      receivedMessage = getEnvelopedData(encodedEnvelopedData, esdhUser1Pk_, 2);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // esdhUser2
      System.out.println("\nDecrypt for esdhUser2:");
      receivedMessage = getEnvelopedData(encodedEnvelopedData, esdhUser2Pk_, 2);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // kekUser
      System.out.println("\nDecrypt for kekUser:");
      receivedMessage = getEnvelopedData(encodedEnvelopedData, kek_, 3);
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
      // rsaUser1
      System.out.println("\nDecrypt for rsaUser1:");
      receivedMessage = getEnvelopedDataStream(encodedEnvelopedData, rsaUser1Pk_, new IssuerAndSerialNumber(rsaUser1_));
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // rsaUser2
      System.out.println("\nDecrypt for rsaUser2:");
      receivedMessage = getEnvelopedDataStream(encodedEnvelopedData, rsaUser2Pk_, new SubjectKeyID(rsaUser2_));
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // esdhUser1
      System.out.println("\nDecrypt for esdhUser1:");
      receivedMessage = getEnvelopedDataStream(encodedEnvelopedData, esdhUser1Pk_, new IssuerAndSerialNumber(esdhUser1_));
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // esdhUser2
      System.out.println("\nDecrypt for esdhUser2:");
      receivedMessage = getEnvelopedDataStream(encodedEnvelopedData, esdhUser2Pk_, new RecipientKeyIdentifier(esdhUser2_));
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // kekUser
      System.out.println("\nDecrypt for kekUser:");
      receivedMessage = getEnvelopedDataStream(encodedEnvelopedData, kek_, new KEKIdentifier(kekID_));
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
    } else {
      // rsaUser1
      System.out.println("\nDecrypt for rsaUser1:");
      receivedMessage = getEnvelopedData(encodedEnvelopedData, rsaUser1Pk_, new IssuerAndSerialNumber(rsaUser1_));
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
       // rsaUser2
      System.out.println("\nDecrypt for rsaUser2:");
      receivedMessage = getEnvelopedData(encodedEnvelopedData, rsaUser2Pk_, new SubjectKeyID(rsaUser2_));
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // esdhUser1
      System.out.println("\nDecrypt for esdhUser1:");
      receivedMessage = getEnvelopedData(encodedEnvelopedData, esdhUser1Pk_, new IssuerAndSerialNumber(esdhUser1_));
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // esdhUser2
      System.out.println("\nDecrypt for esdhUser2:");
      receivedMessage = getEnvelopedData(encodedEnvelopedData, esdhUser2Pk_, new RecipientKeyIdentifier(esdhUser2_));
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // kekUser
      System.out.println("\nDecrypt for kekUser:");
      receivedMessage = getEnvelopedData(encodedEnvelopedData, kek_, new KEKIdentifier(kekID_));
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
    }    
  }
  
  /**
   * Parses an EnvelopedData and decrypts the content for all test recipients
   * using their recipient certificate (for RecipientInfos of type KeyTransRecipientInfo
   * or KeyAgreeRecipientInfo) or key id (for RecipientInfos of type KEKRecipientInfo)
   * for identifying the recipient.
   *
   * @param stream whether to use EnvelopedDataStream or EnvelopedData
   * @param encodedEnvelopedData the encoded EnvelopedData object 
   *
   * @exception Exception if some error occurs during decoding/decryption
   */ 
  public void parseEnvelopedDataWithRecipientCertOrKEKId(boolean stream, byte[] encodedEnvelopedData) throws Exception {
    byte[] receivedMessage;
    if (stream) {
      // rsaUser1
      System.out.println("\nDecrypt for rsaUser1:");
      receivedMessage = getEnvelopedDataStream(encodedEnvelopedData, rsaUser1Pk_, rsaUser1_, null);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // rsaUser2
      System.out.println("\nDecrypt for rsaUser2:");
      receivedMessage = getEnvelopedDataStream(encodedEnvelopedData, rsaUser2Pk_, rsaUser2_, null);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // esdhUser1
      System.out.println("\nDecrypt for esdhUser1:");
      receivedMessage = getEnvelopedDataStream(encodedEnvelopedData, esdhUser1Pk_, esdhUser1_, null);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // esdhUser2
      System.out.println("\nDecrypt for esdhUser2:");
      receivedMessage = getEnvelopedDataStream(encodedEnvelopedData, esdhUser2Pk_, esdhUser2_, null);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // kekUser
      System.out.println("\nDecrypt for kekUser:");
      receivedMessage = getEnvelopedDataStream(encodedEnvelopedData, kek_, null, kekID_);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
    } else {
      // rsaUser1
      System.out.println("\nDecrypt for rsaUser1:");
      receivedMessage = getEnvelopedData(encodedEnvelopedData, rsaUser1Pk_, rsaUser1_, null);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
       // rsaUser2
      System.out.println("\nDecrypt for rsaUser2:");
      receivedMessage = getEnvelopedData(encodedEnvelopedData, rsaUser2Pk_, rsaUser2_, null);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // esdhUser1
      System.out.println("\nDecrypt for esdhUser1:");
      receivedMessage = getEnvelopedData(encodedEnvelopedData, esdhUser1Pk_, esdhUser1_, null);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // esdhUser2
      System.out.println("\nDecrypt for esdhUser2:");
      receivedMessage = getEnvelopedData(encodedEnvelopedData, esdhUser2Pk_, esdhUser2_, null);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // kekUser
      System.out.println("\nDecrypt for kekUser:");
      receivedMessage = getEnvelopedData(encodedEnvelopedData, kek_, null, kekID_);
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
      byte[] data;
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
      System.out.println("Decrypt for the several recipients using their index into the recipientInfos field.");
      parseEnvelopedDataWithRecipientInfoIndex(true, data);
      System.out.println("Decrypt for the several recipients using their RecipientIdentifier.");
      parseEnvelopedDataWithRecipientIdentifier(true, data);
      System.out.println("Decrypt for the several recipients using their certificate or symmetric kek.");
      parseEnvelopedDataWithRecipientCertOrKEKId(true, data);

      // the non-stream implementation
      System.out.println("\nNon-stream implementation demos");
      System.out.println("===============================");

            
      //
      // test CMS EnvelopedData
      //
      System.out.println("\nCMS EnvelopedData demo [create]:\n");
      data = createEnvelopedData(message);
      // transmit data
      System.out.println("\nCMS EnvelopedData demo [parse]:\n");
      System.out.println("Decrypt for the several recipients using their index into the recipientInfos field.");
      parseEnvelopedDataWithRecipientInfoIndex(false, data);
      System.out.println("Decrypt for the several recipients using their RecipientIdentifier.");
      parseEnvelopedDataWithRecipientIdentifier(false, data);
      System.out.println("Decrypt for the several recipients using their certificate or symmetric kek.");
      parseEnvelopedDataWithRecipientCertOrKEKId(false, data);
      

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
   *            and certificates from files
   */
  public static void main(String argv[]) throws Exception {

   	DemoUtil.initDemos();
    (new EnvelopedDataDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
