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
// $Header: /IAIK-CMS/current/src/demo/cms/authenticatedData/AuthenticatedDataDemo.java 14    23.08.13 14:18 Dbratko $
// $Revision: 14 $

package demo.cms.authenticatedData;


import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.cms.AuthenticatedData;
import iaik.cms.AuthenticatedDataStream;
import iaik.cms.CMSAlgorithmID;
import iaik.cms.CMSException;
import iaik.cms.CertificateIdentifier;
import iaik.cms.IssuerAndSerialNumber;
import iaik.cms.KEKIdentifier;
import iaik.cms.KEKRecipientInfo;
import iaik.cms.KeyAgreeRecipientInfo;
import iaik.cms.KeyIdentifier;
import iaik.cms.KeyTransRecipientInfo;
import iaik.cms.OriginatorInfo;
import iaik.cms.RecipientInfo;
import iaik.cms.RecipientKeyIdentifier;
import iaik.cms.SubjectKeyID;
import iaik.cms.attributes.CMSContentType;
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

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import demo.DemoUtil;
import demo.keystore.CMSKeyStore;

/**
 * Demonstrates the usage of class {@link iaik.cms.AuthenticatedDataStream} and
 * {@link iaik.cms.AuthenticatedData} for recipient-specific protecting the 
 * integrity of a message using the CMS type AuthenticatedData.
 * <p>
 * 
 * <b>Attention:</b> This demo uses Static-Static Diffie-Hellman as key management 
 * technique for providing origin authentication. The mac key is wrapped by
 * using the HMACwith3DESwrap algorithm as specified by RFC 3537. Since this 
 * algorithm is not implemented by IAIK-JCE versions prior 3.12, this demo
 * at least may require IAIK-JCE 3.12 as cryptographic service provider.
 * <p>
 * This demo requires that you have <code>iaik_esdh.jar</code>
 * (or <code>iaik_jce_full.jar</code>) in your classpath.
 * You can download iaik_esdh.jar from <a href="http://jce.iaik.tugraz.at/download/">
 * http://jce.iaik.tugraz.at/download/</a>.
 * 
 *
 * @see iaik.cms.AuthenticatedDataStream
 * @see iaik.cms.AuthenticatedData
 * 
 * @author Dieter Bratko
 */
public class AuthenticatedDataDemo {
  
  // certificate of rsaUser 1
  X509Certificate rsaUser1Cert_;
  // private key of rsaUser 1
  PrivateKey rsaUser1PrivKey_;
  // certificate of rsaUser 2
  X509Certificate rsaUser2Cert_;
  // private key of rsaUser 2
  PrivateKey rsaUser2PrivKey_;

  // certificate of (originator) User 1 (static-static Diffie-Hellman)
  X509Certificate ssdhUser1Cert_;
  X509Certificate[] originatorCerts_;
  // private key of SSDH User 1
  PrivateKey ssdhUser1PrivKey_;
  // certificate of SSDH User 2 (static-static Diffie-Hellman)
  X509Certificate ssdhUser2Cert_;
  // private key of SSDH User 2
  PrivateKey ssdhUser2PrivKey_;
  
  // key wrap algorithm to be used
  AlgorithmID keyWrapAlg_;
  // kek length
  int kekLength_;
  // key encryption key for KEKRecipientInfo
  SecretKey kek_;
  byte[] kekID_;

  
  // secure random number generator
  SecureRandom random_;
  
  /**
   * Creates and AuthenticatedDataDemo object and setups the demo certificates.
   *
   * Keys and certificate are retrieved from the demo KeyStore which
   * has to be located in your current working directory and may be
   * created by running {@link demo.keystore.SetupCMSKeyStore
   * SetupCMSKeyStore}.
   * <p>
   * HMACwith3DESwrap is used as key wrap algorithm.
   *
   * @exception IOException if an file read error occurs
   */
  public AuthenticatedDataDemo() throws IOException {
    this((AlgorithmID)CMSAlgorithmID.cms_HMACwith3DES_wrap.clone(), 192);
  }

  /**
   * Creates and AuthenticatedDataDemo object and setups the demo certificates.
   *
   * Keys and certificate are retrieved from the demo KeyStore which
   * has to be located in your current working directory and may be
   * created by running {@link demo.keystore.SetupCMSKeyStore
   * SetupCMSKeyStore}.
   * 
   * @param keyWrapAlg the key wrap algorithm to be used
   * @param kekLength the length of the key encryption key
   *
   * @exception IOException if an file read error occurs
   */
  public AuthenticatedDataDemo(AlgorithmID keyWrapAlg, int kekLength) throws IOException {
    
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                           AuthenticatedDataDemo                                *");
    System.out.println("*        (shows the usage of the CMS AuthenticatedData type implementation)      *");
    System.out.println("**********************************************************************************");
    System.out.println();
    
    // add all certificates to the list
    rsaUser1Cert_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT)[0];
    rsaUser1PrivKey_ = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT);
    rsaUser2Cert_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_)[0];
    rsaUser2PrivKey_ = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_);
    
    originatorCerts_ = CMSKeyStore.getCertificateChain(CMSKeyStore.SSDH, CMSKeyStore.SZ_1024_CRYPT);
    ssdhUser1Cert_ = originatorCerts_[0];
    ssdhUser1PrivKey_ = CMSKeyStore.getPrivateKey(CMSKeyStore.SSDH, CMSKeyStore.SZ_1024_CRYPT);
    ssdhUser2Cert_ = CMSKeyStore.getCertificateChain(CMSKeyStore.SSDH, CMSKeyStore.SZ_1024_CRYPT_)[0];
    ssdhUser2PrivKey_ = CMSKeyStore.getPrivateKey(CMSKeyStore.SSDH, CMSKeyStore.SZ_1024_CRYPT_);
    
    random_ = SecRandom.getDefault();
    keyWrapAlg_ = keyWrapAlg;
    kekLength_ = kekLength;
    //  create a secret key encryption key for a KEKRecipientInfo
    KeyGenerator kg;
    try {
      kg = keyWrapAlg_.getKeyGeneratorInstance("IAIK");
    } catch (NoSuchAlgorithmException ex) {
      throw new IOException("KeyGenerator not available: " + ex.toString());   
    }   
    kg.init(random_);
    kek_ = kg.generateKey();
    kekID_ = new byte[] { 00, 00, 00, 01 };
    
  }


  /**
   * Creates a CMS <code>AuthenticatedDataStream</code> for the given message message.
   *
   * @param message the message to be authenticated, as byte representation
   * @param macAlgorithm the mac algorithm to be used
   * @param macKeyLength the length of the temporary MAC key to be generated
   * @param digestAlgorithm the digest algorithm to be used to calculate a digest
   *                        from the content if authenticated attributes should
   *                        be included
   * @return the BER encoding of the <code>AuthenticatedData</code> object just created
   * @exception CMSException if the <code>AuthenticatedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createAuthenticatedDataStream(byte[] message,
                                              AlgorithmID macAlgorithm,
                                              int macKeyLength,
                                              AlgorithmID digestAlgorithm,
                                              int mode)
    throws CMSException, IOException {
    
    AlgorithmID macAlg = (AlgorithmID)macAlgorithm.clone();
    AlgorithmID digestAlg = null;
    if (digestAlgorithm != null) {
       digestAlg = (AlgorithmID)digestAlgorithm.clone();
    }   
    ObjectID contentType = ObjectID.cms_data;
    
    AuthenticatedDataStream authenticatedData;

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);
    // create a new AuthenticatedData object 
    try {
      authenticatedData = new AuthenticatedDataStream(contentType,
                                                      is, 
                                                      macAlg,
                                                      macKeyLength,
                                                      null,
                                                      digestAlg,
                                                      mode);
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException(ex.toString());
    }

    // static-static mode: set OriginatorInfo
    OriginatorInfo originator = new OriginatorInfo();
    originator.setCertificates(originatorCerts_);
    authenticatedData.setOriginatorInfo(originator);
    // create the recipient infos
    RecipientInfo[] recipients = createRecipients();
    // specify the recipients of the authenticated message
    authenticatedData.setRecipientInfos(recipients);
    
    if (digestAlgorithm != null) {
       // create some authenticated attributes
       // (the message digest attribute is automatically added)
       try {
         Attribute[] attributes = { new Attribute(new CMSContentType(contentType)) };
         authenticatedData.setAuthenticatedAttributes(attributes);
       } catch (Exception ex) {
         throw new CMSException("Error creating attribute: " + ex.toString());   
       } 
    }    
    
    // in explicit mode get the content and write it  to any out-of-band place
    if (mode == AuthenticatedDataStream.EXPLICIT) {
      InputStream data_is = authenticatedData.getInputStream();
      byte[] buf = new byte[1024];
      int r;
      while ((r = data_is.read(buf)) > 0)
        ;   // skip data
    }    
      

    // return the AuthenticatedDate as BER encoded byte array with block size 2048
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    authenticatedData.writeTo(os, 2048);
    return os.toByteArray();
  }

  /**
   * Decrypts the encrypted MAC key for the recipient identified by its index
   * into the recipientInfos field and uses the MAC key to verify
   * the authenticated data.
   * <p>
   * This way of decrypting the MAC key and verifying the content may be used for 
   * any type of RecipientInfo (KeyTransRecipientInfo, KeyAgreeRecipientInfo, 
   * KEKRecipientInfo, PasswordRecipeintInfo, OtherRecipientInfo), but requires to 
   * know at what index of the recipientInfos field the RecipientInfo for the 
   * particular recipient in mind can be found. 
   * If the recipient in mind uses a RecipientInfo of type KeyAgreeRecipientInfo
   * some processing overhead may take place because a KeyAgreeRecipientInfo may
   * contain encrypted mac keys for more than only one recipient; since the
   * recipientInfoIndex only specifies the RecipientInfo but not the encrypted
   * mac key -- if there are more than only one -- repeated decryption runs may be
   * required as long as the decryption process completes successfully.
   *
   * @param encoding the <code>AuthenticatedData</code> object as BER encoded byte array
   * @param message the content message, if transmitted by other means (explicit mode)
   * @param key the key to decrypt the mac key 
   * @param recipientInfoIndex the index of the right <code>RecipientInfo</code> to 
   *                           which the given key belongs
   *
   * @return the verified message, as byte array
   * 
   * @exception CMSException if the authenticated data cannot be verified
   * @exception IOException if a stream read/write error occurs
   */
  public byte[] getAuthenticatedDataStream(byte[] encoding, 
                                           byte[] message, 
                                           Key key, 
                                           int recipientInfoIndex)
    throws CMSException, IOException {

    // create the AuthenticatedData object from a DER encoded byte array
    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    AuthenticatedDataStream authenticatedData = new AuthenticatedDataStream(is);
    
    if (authenticatedData.getMode() == AuthenticatedDataStream.EXPLICIT) {
      // in explicit mode explicitly supply the content for hash/mac computation  
      authenticatedData.setInputStream(new ByteArrayInputStream(message));
    }

    System.out.println("\nThis message can be verified by the following recipients:");
    RecipientInfo[] recipients = authenticatedData.getRecipientInfos();
    
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
    // decrypt the mac key and verify the mac for the indented recipient
    try {
      authenticatedData.setupMac(key, recipientInfoIndex);
      InputStream contentStream = authenticatedData.getInputStream();
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      Util.copyStream(contentStream, os, null);
      
      if (authenticatedData.verifyMac() == false) {
        throw new CMSException("Mac verification error!");
      }  
      System.out.println("Mac successfully verified!");
      
      return os.toByteArray();

    } catch (InvalidKeyException ex) {
      throw new CMSException("Key error: "+ex.getMessage());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException(ex.toString());
    }
  }
  
  /**
   * Decrypts the encrypted MAC key for the recipient identified by recipient identifier
   * and uses the MAC key to verify the authenticated data.
   * <p>
   * This way of decrypting the mac key may be used for any type of RecipientInfo
   * (KeyTransRecipientInfo, KeyAgreeRecipientInfo, KEKRecipientInfo). The 
   * recipient in mind is identified by its recipient identifier.
   *
   * @param encoding the <code>AuthenticatedData</code> object as BER encoded byte array
   * @param key the key to decrypt the encrypted mac key
   * @param recipientID the recipient identifier uniquely identifying the key of the
   *        recipient
   *
   * @return the verified message, as byte array
   * 
   * @exception CMSException if the authenticated data cannot be verified
   * @exception IOException if a stream read/write error occurs
   */
  public byte[] getAuthenticatedDataStream(byte[] encoding, 
                                           byte[] message,
                                           Key key, 
                                           KeyIdentifier recipientID)
    throws CMSException, IOException {

    // create the AuthenticatedData object from a BER encoded byte array
    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    AuthenticatedDataStream authenticatedData = new AuthenticatedDataStream(is);
    
    if (authenticatedData.getMode() == AuthenticatedDataStream.EXPLICIT) {
      // in explicit mode explicitly supply the content for hash/mac computation  
      authenticatedData.setInputStream(new ByteArrayInputStream(message));
    }
   
    // get the right RecipientInfo
    System.out.println("\nSearch for RecipientInfo:");
    RecipientInfo recipient = authenticatedData.getRecipientInfo(recipientID);
    if (recipient != null) {
      System.out.println("RecipientInfo: " + recipient);   
    } else {
      throw new CMSException("No recipient with ID: " + recipientID);
    }
    // decrypt the mac key and verify the content mac
    try {
      System.out.println("Decrypt encrypted mac key...");
      SecretKey cek = recipient.decryptKey(key, recipientID);
      System.out.println("Verify content mac with decrypted mac key...");
      authenticatedData.setupMac(cek);
      InputStream contentStream = authenticatedData.getInputStream();
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      Util.copyStream(contentStream, os, null);
      
      if (authenticatedData.verifyMac() == false) {
        throw new CMSException("Mac verification error!");
      } 
      System.out.println("Mac successfully verified!");

      return os.toByteArray();

    } catch (InvalidKeyException ex) {
      throw new CMSException("Key error: "+ex.getMessage());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException(ex.toString());
    }
  }
  
  /**
   * Decrypts the encrypted content of the given <code>AuthenticatedData</code> object for
   * the recipient identified by its recipient certificate or kekID.
   * <p>
   *
   * @param encoding the <code>AuthenticatedData</code> object as DER encoded byte array
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
  public byte[] getAuthenticatedDataStream(byte[] encoding, 
                                           byte[] message,
                                           Key key, 
                                           X509Certificate recipientCert,
                                           byte[] kekID)
    throws CMSException, IOException {

    // create the AuthenticatedData object from a DER encoded byte array
    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    AuthenticatedDataStream authenticatedData = new AuthenticatedDataStream(is);
    
    if (authenticatedData.getMode() == AuthenticatedDataStream.EXPLICIT) {
      // in explicit mode explicitly supply the content for hash/mac computation  
      authenticatedData.setInputStream(new ByteArrayInputStream(message));
    }

   
    // decrypt the mac key and verify the content mac
    try {
      System.out.println("Verify mac...");
      if (recipientCert != null) {
        authenticatedData.setupMac(key, recipientCert);
      } else {
        // KEKRecipientInfo
        authenticatedData.setupMac(key, new KEKIdentifier(kekID));
      }
      InputStream contentStream = authenticatedData.getInputStream();
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      Util.copyStream(contentStream, os, null);
      
      if (authenticatedData.verifyMac() == false) {
        throw new CMSException("Mac verification error!");
      }
      System.out.println("Mac successfully verified!");

      return os.toByteArray();

    } catch (InvalidKeyException ex) {
      throw new CMSException("Key error: "+ex.getMessage());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException(ex.toString());
    }
  }


  // non stream

  /**
   * Creates a CMS <code>AuthenticatedDataStream</code> for the given message message.
   *
   * @param message the message to be authenticated, as byte representation
   * @param macAlgorithm the mac algorithm to be used
   * @param macKeyLength the length of the temporary MAC key to be generated
   * @param digestAlgorithm the digest algorithm to be used to calculate a digest
   *                        from the content if authenticated attributes should
   *                        be included
   * @return the BER encoding of the <code>AuthenticatedData</code> object just created
   * @exception CMSException if the <code>AuthenticatedData</code> object cannot
   *                          be created
   */
  public byte[] createAuthenticatedData(byte[] message,
                                        AlgorithmID macAlgorithm,
                                        int macKeyLength,
                                        AlgorithmID digestAlgorithm,
                                        int mode)
    throws CMSException {
        
    AlgorithmID macAlg = (AlgorithmID)macAlgorithm.clone();
    AlgorithmID digestAlg = null;
    if (digestAlgorithm != null) {
       digestAlg = (AlgorithmID)digestAlgorithm.clone();
    }   
    ObjectID contentType = ObjectID.cms_data;
    
    AuthenticatedData authenticatedData;

    // create a new AuthenticatedData object 
    try {
      authenticatedData = new AuthenticatedData(contentType,
                                                message, 
                                                macAlg,
                                                macKeyLength,
                                                null,
                                                digestAlg,
                                                mode);
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException(ex.toString());
    }

    // static-static mode: set OriginatorInfo
    OriginatorInfo originator = new OriginatorInfo();
    originator.setCertificates(originatorCerts_);
    authenticatedData.setOriginatorInfo(originator);
    // create the recipient infos
    RecipientInfo[] recipients = createRecipients();
    // specify the recipients of the authenticated message
    authenticatedData.setRecipientInfos(recipients);
    
    if (digestAlgorithm != null) {
       // create some authenticated attributes
       // (the message digest attribute is automatically added)
       try {
         Attribute[] attributes = { new Attribute(new CMSContentType(contentType)) };
         authenticatedData.setAuthenticatedAttributes(attributes);
       } catch (Exception ex) {
         throw new CMSException("Error creating attribute: " + ex.toString());   
       } 
    }    
   
    // return the AuthenticatedData as DER encoded byte array
    return authenticatedData.getEncoded();
  
  }


  /**
   * Decrypts the encrypted MAC key for the recipient identified by its index
   * into the recipientInfos field and uses the MAC key to verify
   * the authenticated data.
   * <p>
   * This way of decrypting the MAC key and verifying the content may be used for 
   * any type of RecipientInfo (KeyTransRecipientInfo, KeyAgreeRecipientInfo, 
   * KEKRecipientInfo), but requires to know at what index of the recipientInfos
   * field the RecipientInfo for the particular recipient in mind can be found. 
   * If the recipient in mind uses a RecipientInfo of type KeyAgreeRecipientInfo
   * some processing overhead may take place because a KeyAgreeRecipientInfo may
   * contain encrypted mac keys for more than only one recipient; since the
   * recipientInfoIndex only specifies the RecipientInfo but not the encrypted
   * mac key -- if there are more than only one -- repeated decryption runs may be
   * required as long as the decryption process completes successfully.
   *
   * @param encoding the <code>AuthenticatedData</code> object as BER encoded byte array
   * @param message the content message, if transmitted by other means (explicit mode)
   * @param key the key to decrypt the mac key
   * @param recipientInfoIndex the index of the right <code>RecipientInfo</code> to 
   *                           which the given key belongs
   *
   * @return the verified message, as byte array
   * @exception CMSException if the authenticated data cannot be verified
   * @exception IOException if a IO read/write error occurs
   */
  public byte[] getAuthenticatedData(byte[] encoding, 
                                     byte[] message,
                                     Key key,
                                     int recipientInfoIndex) 
    throws CMSException, IOException {
        
    // create the AuthenticatedData object from a DER encoded byte array
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    AuthenticatedData authenticatedData = new AuthenticatedData(is);
    
    if (authenticatedData.getMode() == AuthenticatedData.EXPLICIT) {
      // in explicit mode explicitly supply the content for hash/mac computation  
      authenticatedData.setContent(message);
    }

    System.out.println("\nThis message can be verified by the owners of the following recipients:");
    RecipientInfo[] recipients = authenticatedData.getRecipientInfos();
    
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
    // decrypt the mac key and verify the mac for the first recipient
    try {
      authenticatedData.setupMac(key, recipientInfoIndex);
      if (authenticatedData.verifyMac() == false) {
        throw new CMSException("Mac verification error!");
      }  
      System.out.println("Mac successfully verified!");
      
      return authenticatedData.getContent();

    } catch (InvalidKeyException ex) {
      throw new CMSException("Key error: "+ex.getMessage());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException(ex.toString());
    }
  }
  
  /**
   * Decrypts the encrypted content of the given <code>AuthenticatedData</code> object for
   * the recipient identified by recipient identifier.
   * <p>
   * This way of decrypting the content may be used for any type of RecipientInfo
   * (KeyTransRecipientInfo, KeyAgreeRecipientInfo, KEKRecipientInfo). The 
   * recipient in mind is identified by its recipient identifier.
   *
   * @param encoding the DER encoeded <code>AuthenticatedData</code> object
   * @param key the key to decrypt the message
   * @param recipientID the recipient identifier uniquely identifying the key of the
   *        recipient
   *
   * @return the recovered message, as byte array
   * @exception CMSException if the message cannot be recovered
   * @exception IOException if an I/O error occurs
   */
  public byte[] getAuthenticatedData(byte[] encoding, 
                                     byte[] message,
                                     Key key, 
                                     KeyIdentifier recipientID) 
    throws CMSException, IOException {
        
    // create the AuthenticatedData object from a DER encoded byte array
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    AuthenticatedData authenticatedData = new AuthenticatedData(is);
    
    if (authenticatedData.getMode() == AuthenticatedData.EXPLICIT) {
      // in explicit mode explicitly supply the content for hash/mac computation  
      authenticatedData.setContent(message);
    }
   
    // get the right RecipientInfo
    System.out.println("\nSearch for RecipientInfo:");
    RecipientInfo recipient = authenticatedData.getRecipientInfo(recipientID);
    if (recipient != null) {
      System.out.println("RecipientInfo: " + recipient);   
    } else {
      throw new CMSException("No recipient with ID " + recipientID);
    }
    // decrypt the mac key and verify the content mac
    try {
      System.out.println("Decrypt encrypted mac key...");
      SecretKey cek = recipient.decryptKey(key, recipientID);
      System.out.println("Verify content mac with decrypted mac key...");
      authenticatedData.setupMac(cek);
      
      if (authenticatedData.verifyMac() == false) {
        throw new CMSException("Mac verification error!");
      } 
      System.out.println("Mac successfully verified!");

      return authenticatedData.getContent();

    } catch (InvalidKeyException ex) {
      throw new CMSException("Key error: "+ex.getMessage());
    } 
  }
  
  /**
   * Decrypts the encrypted content of the given <code>AuthenticatedData</code> object for
   * the recipient identified by its recipient certificate or kekID.
   * <p>
   *
   * @param encoding the DER encoded <code>AuthenticatedData</code> ASN.1 object
   * @param key the key to decrypt the message
   * @param recipientCert the certificate of the recipient having a RecipientInfo of
   *                      type KeyTransRecipientInfo or KeyAgreeRecipientInfo
   * @param kekID the kekID identifying the recipient key when using a RecipientInfo
   *              of type KEKRecipientInfo                      
   *
   * @return the recovered message, as byte array
   * @exception CMSException if the message cannot be recovered
   */
  public byte[] getAuthenticatedData(byte[] encoding, 
                                     byte[] message,
                                     Key key,
                                     X509Certificate recipientCert,
                                     byte[] kekID) 
    throws CMSException, IOException {

    // create the AuthenticatedData object from a DER encoded byte array
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    AuthenticatedData authenticatedData = new AuthenticatedData(is);
    
    if (authenticatedData.getMode() == AuthenticatedData.EXPLICIT) {
      // in explicit mode explicitly supply the content for hash/mac computation  
      authenticatedData.setContent(message);
    }

    // decrypt the mac key and verify the content mac
    try {
      System.out.println("Verify mac...");
      if (recipientCert != null) {
        authenticatedData.setupMac(key, recipientCert);
      } else {
        // KEKRecipientInfo
        authenticatedData.setupMac(key, new KEKIdentifier(kekID));
      }
    
      if (authenticatedData.verifyMac() == false) {
        throw new CMSException("Mac verification error!");
      }
      System.out.println("Mac successfully verified!");

      return authenticatedData.getContent();
      
    } catch (InvalidKeyException ex) {
      throw new CMSException("Key error: "+ex.getMessage());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException(ex.toString());
    } 
  }
  
  /**
   * Creates the RecipientInfos.
   *
   * @return the RecipientInfos created
   *
   * @exception CMSException if an error occurs when creating the recipient infos
   */
  public RecipientInfo[] createRecipients() throws CMSException {
    
    RecipientInfo[] recipients = new RecipientInfo[4];
    try {
      
      // rsaUser1 is the first receiver (cert identified by IssuerAndSerialNumber)
      recipients[0] = new KeyTransRecipientInfo(rsaUser1Cert_, 
                                                (AlgorithmID)AlgorithmID.rsaEncryption.clone());
      // rsaUser2 is the second receiver (cert identifief by SubjectKeyIdentifier)
      recipients[1] = new KeyTransRecipientInfo(rsaUser2Cert_,
                                                CertificateIdentifier.SUBJECT_KEY_IDENTIFIER, 
                                                (AlgorithmID)AlgorithmID.rsaEncryption.clone());
      
      // next recipients use key agreement (Static-Static Diffie-Hellman)
      // the key encryption (key agreement) algorithm to use:
      AlgorithmID keyEA = (AlgorithmID)AlgorithmID.ssdhKeyAgreement.clone();
      // the key wrap algorithm to use:
      AlgorithmID keyWrapAlg = (AlgorithmID)keyWrapAlg_.clone();
      // the length of the key encryption key to be generated:
      int kekLength = kekLength_;
      // in static-static mode we may supply user keying material
      byte[] ukm = new byte[64];
      random_.nextBytes(ukm);
      // ssdhUser1 is originator
      recipients[2] = new KeyAgreeRecipientInfo(ssdhUser1Cert_, 
                                                ssdhUser1PrivKey_,
                                                KeyIdentifier.ISSUER_AND_SERIALNUMBER,
                                                keyEA, 
                                                keyWrapAlg, 
                                                kekLength, 
                                                ukm);
      // add ssdhUser1 (originator) as recipient, too
      ((KeyAgreeRecipientInfo)recipients[2]).addRecipient(ssdhUser1Cert_, CertificateIdentifier.ISSUER_AND_SERIALNUMBER);
      // ssdhUser2 is the recipient (cert identified by RecipientKeyIdentifier)
      ((KeyAgreeRecipientInfo)recipients[2]).addRecipient(ssdhUser2Cert_, CertificateIdentifier.RECIPIENT_KEY_IDENTIFIER);

      // last receiver uses a symmetric key encryption key  
      AlgorithmID kea = (AlgorithmID)CMSAlgorithmID.cms_HMACwith3DES_wrap.clone();
      KEKIdentifier kekIdentifier = new KEKIdentifier(kekID_);
      recipients[3] = new KEKRecipientInfo(kekIdentifier, kea, kek_);
      
    } catch (Exception ex) {
      throw new CMSException("Error adding recipients: " + ex.getMessage()); 
    }    
    return recipients;
  }  
  
  /**
   * Parses an AuthenticatedData and decrypts the content for all test recipients
   * using the index into the recipientInfos field for identifying the recipient.
   *
   * @param stream whether to use AuthenticatedDataStream or AuthenticatedData
   * @param encodedAuthenticatedData the encoded AuthenticatedData object 
   *
   * @exception Exception if some error occurs during mac key decryption / mac verification
   */ 
  public void parseAuthenticatedDataWithRecipientInfoIndex(boolean stream, 
                                                           byte[] encodedAuthenticatedData,
                                                           byte[] message) 
    throws Exception {
    
    byte[] receivedMessage;
    if (stream) {
      
      // rsaUser1
      System.out.println("\nVerify MAC for rsaUser1:");
      
      receivedMessage = getAuthenticatedDataStream(encodedAuthenticatedData, 
                                                    message,
                                                    rsaUser1PrivKey_,
                                                    0);
      System.out.print("\nContent: ");
      System.out.println(new String(receivedMessage));
        
      // rsaUser2
      System.out.println("\nVerify MAC for rsaUser2:");
      receivedMessage = getAuthenticatedDataStream(encodedAuthenticatedData, 
                                                    message,
                                                    rsaUser2PrivKey_,
                                                    1);
      
      // ssdhUser1
      System.out.println("\nVerify MAC for ssdhUser1:");
    
      receivedMessage = getAuthenticatedDataStream(encodedAuthenticatedData, 
                                                    message,
                                                    ssdhUser1PrivKey_,
                                                    2);
      System.out.print("\nContent: ");
      System.out.println(new String(receivedMessage));
      
      // ssdhUser2
      System.out.println("\nVerify MAC for ssdhUser2:");
      receivedMessage = getAuthenticatedDataStream(encodedAuthenticatedData, 
                                                    message,
                                                    ssdhUser2PrivKey_,
                                                    2);
      System.out.print("\nContent: ");
      System.out.println(new String(receivedMessage));
      
      // kekUser
      System.out.println("\nVerify MAC for kekUser:");
      receivedMessage = getAuthenticatedDataStream(encodedAuthenticatedData,
                                                    message,
                                                    kek_,
                                                    3);
      System.out.print("\nContent: ");
      System.out.println(new String(receivedMessage));
      
    } else {
      
      // rsaUser1
      System.out.println("\nVerify MAC for rsaUser1:");
      
      receivedMessage = getAuthenticatedData(encodedAuthenticatedData, 
                                              message,
                                              rsaUser1PrivKey_,
                                              0);
      System.out.print("\nContent: ");
      System.out.println(new String(receivedMessage));
        
      // rsaUser2
      System.out.println("\nVerify MAC for rsaUser2:");
      receivedMessage = getAuthenticatedData(encodedAuthenticatedData, 
                                              message,
                                              rsaUser2PrivKey_,
                                              1); 
      
      // ssdhUser1
      System.out.println("\nVerify MAC for ssdhUser1:");
      receivedMessage = getAuthenticatedData(encodedAuthenticatedData, 
                                              message, 
                                              ssdhUser1PrivKey_,
                                              2);
      System.out.print("\nContent: ");
      System.out.println(new String(receivedMessage));
       // ssdhUser2
      System.out.println("\nVerify MAC for ssdhUser2:");
      receivedMessage = getAuthenticatedData(encodedAuthenticatedData, 
                                              message, 
                                              ssdhUser2PrivKey_, 
                                              2);
      
      // kekUser
      System.out.println("\nVerify MAC for kekUser:");
      receivedMessage = getAuthenticatedData(encodedAuthenticatedData,
                                              message,
                                              kek_,
                                              3);
      
      System.out.print("\nContent: ");
      System.out.println(new String(receivedMessage));
    }    
  }
  
  /**
   * Parses an AuthenticatedData, decrypts the mac keys for all test recipients
   * using their recipient identifiers for identifying the recipient
   * and verifies the content mac.
   *
   * @param stream whether to use AuthenticatedDataStream or AuthenticatedData
   * @param encodedAuthenticatedData the encoded AuthenticatedData object 
   *
   * @exception Exception if some error occurs during mac key decryption / mac verification
   */ 
  public void parseAuthenticatedDataWithRecipientIdentifier(boolean stream, 
                                                            byte[] encodedAuthenticatedData,
                                                            byte[] message) 
    throws Exception {
        
    byte[] receivedMessage;
    if (stream) {
      
      // rsaUser1
      System.out.println("\nVerify MAC for rsaUser1:");
      receivedMessage = getAuthenticatedDataStream(encodedAuthenticatedData, 
                                                    message, 
                                                    rsaUser1PrivKey_, 
                                                    new IssuerAndSerialNumber(rsaUser1Cert_));
      System.out.print("\nContent: ");
      System.out.println(new String(receivedMessage));
      
      // rsaUser2
      System.out.println("\nVerify MAC for rsaUser2:");
      receivedMessage = getAuthenticatedDataStream(encodedAuthenticatedData,
                                                    message,
                                                    rsaUser2PrivKey_, 
                                                    new SubjectKeyID(rsaUser2Cert_));

      // ssdhUser1
      System.out.println("\nVerify MAC for ssdhUser1:");
      receivedMessage = getAuthenticatedDataStream(encodedAuthenticatedData, 
                                                    message, 
                                                    ssdhUser1PrivKey_, 
                                                    new IssuerAndSerialNumber(ssdhUser1Cert_));
      System.out.print("\nContent: ");
      System.out.println(new String(receivedMessage));
      // ssdhUser2
      System.out.println("\nVerify MAC for ssdhUser2:");
      receivedMessage = getAuthenticatedDataStream(encodedAuthenticatedData,
                                                    message,
                                                    ssdhUser2PrivKey_, 
                                                    new RecipientKeyIdentifier(ssdhUser2Cert_));
      // kekUser
      System.out.println("\nVerify MAC for kekUser:");
      receivedMessage = getAuthenticatedDataStream(encodedAuthenticatedData,
                                                    message,
                                                    kek_,
                                                    new KEKIdentifier(kekID_));
      
      System.out.print("\nContent: ");
      System.out.println(new String(receivedMessage));
    
    } else {
      
      // rsaUser1
      System.out.println("\nVerify MAC for rsaUser1:");
      receivedMessage = getAuthenticatedDataStream(encodedAuthenticatedData, 
                                                    message, 
                                                    rsaUser1PrivKey_, 
                                                    new IssuerAndSerialNumber(rsaUser1Cert_));
      System.out.print("\nContent: ");
      System.out.println(new String(receivedMessage));
      
      // rsaUser2
      System.out.println("\nVerify MAC for rsaUser2:");
      receivedMessage = getAuthenticatedDataStream(encodedAuthenticatedData,
                                                    message,
                                                    rsaUser2PrivKey_, 
                                                    new SubjectKeyID(rsaUser2Cert_));
      
      // ssdhUser1
      System.out.println("\nVerify MAC for ssdhUser1:");
      receivedMessage = getAuthenticatedData(encodedAuthenticatedData, 
                                              message, 
                                              ssdhUser1PrivKey_, 
                                              new IssuerAndSerialNumber(ssdhUser1Cert_));
      System.out.print("\nContent: ");
      System.out.println(new String(receivedMessage));
       // ssdhUser2
      System.out.println("\nVerify MAC for ssdhUser2:");
      receivedMessage = getAuthenticatedData(encodedAuthenticatedData, 
                                              message, 
                                              ssdhUser2PrivKey_, 
                                              new RecipientKeyIdentifier(ssdhUser2Cert_));
      // kekUser
      System.out.println("\nVerify MAC for kekUser:");
      receivedMessage = getAuthenticatedData(encodedAuthenticatedData,
                                              message,
                                              kek_,
                                              new KEKIdentifier(kekID_));
      
      System.out.print("\nContent: ");
      System.out.println(new String(receivedMessage));
    }    
  }
  
  /**
   * Parses an AuthenticatedData, decrypts the encrypted mac keys for all test recipients
   * using their recipient certificate (or kek) for identifying the recipient
   * and verifies the content mac.
   *
   * @param stream whether to use AuthenticatedDataStream or AuthenticatedData
   * @param encodedAuthenticatedData the encoded AuthenticatedData object 
   *
   * @exception Exception if some error occurs during mac key decryption / mac verification
   */ 
  public void parseAuthenticatedDataWithRecipientCertOrKEKId(boolean stream, 
                                                             byte[] encodedAuthenticatedData,
                                                             byte[] message)
    throws Exception {
    
    byte[] receivedMessage;
    if (stream) {
      
      // rsaUser1
      System.out.println("\nVerify MAC for rsaUser1:");
      receivedMessage = getAuthenticatedDataStream(encodedAuthenticatedData, 
                                                    message, 
                                                    rsaUser1PrivKey_, 
                                                    rsaUser1Cert_,
                                                    null);
      System.out.print("\nContent: ");
      System.out.println(new String(receivedMessage));
      // rsaUser2
      System.out.println("\nVerify MAC for rsaUser2:");
      receivedMessage = getAuthenticatedDataStream(encodedAuthenticatedData,
                                                    message,
                                                    rsaUser2PrivKey_, 
                                                    rsaUser2Cert_,
                                                    null);
      
      // ssdhUser1
      System.out.println("\nVerify MAC for ssdhUser1:");
      receivedMessage = getAuthenticatedDataStream(encodedAuthenticatedData, 
                                                    message, 
                                                    ssdhUser1PrivKey_, 
                                                    ssdhUser1Cert_,
                                                    null);
      System.out.print("\nContent: ");
      System.out.println(new String(receivedMessage));
      // ssdhUser2
      System.out.println("\nVerify MAC for ssdhUser2:");
      receivedMessage = getAuthenticatedDataStream(encodedAuthenticatedData,
                                                    message,
                                                    ssdhUser2PrivKey_, 
                                                    ssdhUser2Cert_,
                                                    null);
      // kekUser
      System.out.println("\nVerify MAC for kekUser:");
      receivedMessage = getAuthenticatedDataStream(encodedAuthenticatedData,
                                                    message,
                                                    kek_, 
                                                    null,
                                                    kekID_);
      
      System.out.print("\nContent: ");
      System.out.println(new String(receivedMessage));
    } else {
      // rsaUser1
      System.out.println("\nVerify MAC for rsaUser1:");
      receivedMessage = getAuthenticatedData(encodedAuthenticatedData, 
                                              message, 
                                              rsaUser1PrivKey_, 
                                              rsaUser1Cert_,
                                              null);
      System.out.print("\nContent: ");
      System.out.println(new String(receivedMessage));
      // rsaUser2
      System.out.println("\nVerify MAC for rsaUser2:");
      receivedMessage = getAuthenticatedData(encodedAuthenticatedData,
                                              message,
                                              rsaUser2PrivKey_, 
                                              rsaUser2Cert_,
                                              null);
      
      // ssdhUser1
      System.out.println("\nVerify MAC for ssdhUser1:");
      receivedMessage = getAuthenticatedData(encodedAuthenticatedData, 
                                              message, 
                                              ssdhUser1PrivKey_, 
                                              ssdhUser1Cert_,
                                              null);
      System.out.print("\nContent: ");
      System.out.println(new String(receivedMessage));
       // ssdhUser2
      System.out.println("\nVerify MAC for ssdhUser2:");
      receivedMessage = getAuthenticatedData(encodedAuthenticatedData, 
                                              message, 
                                              ssdhUser2PrivKey_, 
                                              ssdhUser2Cert_,
                                              null);
      // kekUser
      System.out.println("\nVerify MAC for kekUser:");
      receivedMessage = getAuthenticatedData(encodedAuthenticatedData,
                                              message,
                                              kek_, 
                                              null,
                                              kekID_);
      
      System.out.print("\nContent: ");
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
      byte[] encodedAuthenticatedData;
      
      AlgorithmID macAlgorithm = (AlgorithmID)AlgorithmID.hMAC_SHA1.clone();
      int macKeyLength = 64;
      AlgorithmID digestAlgorithm = (AlgorithmID)AlgorithmID.sha1.clone();
      
      System.out.println("Stream implementation demos");
      System.out.println("===========================");


      // the stream implementation
      //
      // test CMS AuthenticatedDataStream
      //
      
      // implict mode; with authenticated attributes
      System.out.println("\nCMS AuthenticatedDataStream demo with authenticated attributes [create, implicit mode]:\n");
      encodedAuthenticatedData = createAuthenticatedDataStream(message,
                                                               macAlgorithm,
                                                               macKeyLength,
                                                               digestAlgorithm,
                                                               AuthenticatedDataStream.IMPLICIT);
      // transmit data
      System.out.println("\nCMS AuthenticatedDataStream demo [parse, implicit mode]:\n");
      System.out.println("Decrypt and verify for the several recipients using their index into the recipientInfos field.");
      parseAuthenticatedDataWithRecipientInfoIndex(true, encodedAuthenticatedData, null);
      System.out.println("Decrypt and verify for the several recipients using their RecipientIdentifier.");
      parseAuthenticatedDataWithRecipientIdentifier(true, encodedAuthenticatedData, null);
      System.out.println("Decrypt and verify for the several recipients using their certificate or kek.");
      parseAuthenticatedDataWithRecipientCertOrKEKId(true, encodedAuthenticatedData, null);
      
      // implict mode; without authenticated attributes
      System.out.println("\nCMS AuthenticatedDataStream demo without authenticated attributes [create, implicit mode]:\n");
      encodedAuthenticatedData = createAuthenticatedDataStream(message,
                                                               macAlgorithm,
                                                               macKeyLength,
                                                               null,
                                                               AuthenticatedDataStream.IMPLICIT);
      // transmit data
      System.out.println("\nCMS AuthenticatedDataStream demo [parse, implicit mode]:\n");
      System.out.println("Decrypt and verify for the several recipients using their index into the recipientInfos field.");
      parseAuthenticatedDataWithRecipientInfoIndex(true, encodedAuthenticatedData, null);
      System.out.println("Decrypt and verify for the several recipients using their RecipientIdentifier.");
      parseAuthenticatedDataWithRecipientIdentifier(true, encodedAuthenticatedData, null);
      System.out.println("Decrypt and verify for the several recipients using their certificate or kek.");
      parseAuthenticatedDataWithRecipientCertOrKEKId(true, encodedAuthenticatedData, null);
      
  
      // explict mode; with authenticated attributes
      System.out.println("\nCMS AuthenticatedDataStream demo with authenticated attributes [create, explicit mode]:\n");
      encodedAuthenticatedData = createAuthenticatedDataStream(message,
                                                               macAlgorithm,
                                                               macKeyLength,
                                                               digestAlgorithm,
                                                               AuthenticatedDataStream.EXPLICIT);
      // transmit data
      System.out.println("\nCMS AuthenticatedDataStream demo [parse, explicit mode]:\n");
      System.out.println("Decrypt and verify for the several recipients using their index into the recipientInfos field.");
      parseAuthenticatedDataWithRecipientInfoIndex(true, encodedAuthenticatedData, message);
      System.out.println("Decrypt and verify for the several recipients using their RecipientIdentifier.");
      parseAuthenticatedDataWithRecipientIdentifier(true, encodedAuthenticatedData, message);
      System.out.println("Decrypt and verify for the several recipients using their certificate or kek.");
      parseAuthenticatedDataWithRecipientCertOrKEKId(true, encodedAuthenticatedData, message);
      
      // explict mode; without authenticated attributes
      System.out.println("\nCMS AuthenticatedDataStream demo without authenticated attributes [create, explicit mode]:\n");
      encodedAuthenticatedData = createAuthenticatedDataStream(message,
                                                               macAlgorithm,
                                                               macKeyLength,
                                                               null,
                                                               AuthenticatedDataStream.EXPLICIT);
      // transmit data
      System.out.println("\nCMS AuthenticatedDataStream demo [parse, explicit mode]:\n");
      System.out.println("Decrypt and verify for the several recipients using their index into the recipientInfos field.");
      parseAuthenticatedDataWithRecipientInfoIndex(true, encodedAuthenticatedData, message);
      System.out.println("Decrypt and verify for the several recipients using their RecipientIdentifier.");
      parseAuthenticatedDataWithRecipientIdentifier(true, encodedAuthenticatedData, message);
      System.out.println("Decrypt and verify for the several recipients using their certificate or kek.");
      parseAuthenticatedDataWithRecipientCertOrKEKId(true, encodedAuthenticatedData, message);
      
      

      // the non-stream implementation
      System.out.println("\nNon-stream implementation demos");
      System.out.println("===============================");

            
      //
      // test CMS AuthenticatedData
      //
      
      // implict mode; with authenticated attributes
      System.out.println("\nCMS AuthenticatedData demo with authenticated attributes [create, implicit mode]:\n");
      encodedAuthenticatedData = createAuthenticatedData(message,
                                                         macAlgorithm,
                                                         macKeyLength,
                                                         digestAlgorithm,
                                                         AuthenticatedDataStream.IMPLICIT);
      // transmit data
      System.out.println("\nCMS AuthenticatedData demo [parse]:\n");
      System.out.println("Decrypt and verify for the several recipients using their index into the recipientInfos field.");
      parseAuthenticatedDataWithRecipientInfoIndex(false, encodedAuthenticatedData, null);
      System.out.println("Decrypt and verify for the several recipients using their RecipientIdentifier.");
      parseAuthenticatedDataWithRecipientIdentifier(false, encodedAuthenticatedData, null);
      System.out.println("Decrypt and verify for the several recipients using their certificate or kek.");
      parseAuthenticatedDataWithRecipientCertOrKEKId(false, encodedAuthenticatedData, null);
      
      // implict mode; without authenticated attributes
      System.out.println("\nCMS AuthenticatedData demo without authenticated attributes [create, implicit mode]:\n");
      encodedAuthenticatedData = createAuthenticatedData(message,
                                                         macAlgorithm,
                                                         macKeyLength,
                                                         null,
                                                         AuthenticatedDataStream.IMPLICIT);
      // transmit data
      System.out.println("\nCMS AuthenticatedData demo [parse]:\n");
      System.out.println("Decrypt and verify for the several recipients using their index into the recipientInfos field.");
      parseAuthenticatedDataWithRecipientInfoIndex(false, encodedAuthenticatedData, null);
      System.out.println("Decrypt and verify for the several recipients using their RecipientIdentifier.");
      parseAuthenticatedDataWithRecipientIdentifier(false, encodedAuthenticatedData, null);
      System.out.println("Decrypt and verify for the several recipients using their certificate or kek.");
      parseAuthenticatedDataWithRecipientCertOrKEKId(false, encodedAuthenticatedData, null);
      
      
      // explict mode; with authenticated attributes
      System.out.println("\nCMS AuthenticatedData demo with authenticated attributes [create, explicit mode]:\n");
      encodedAuthenticatedData = createAuthenticatedData(message,
                                                         macAlgorithm,
                                                         macKeyLength,
                                                         digestAlgorithm,
                                                         AuthenticatedDataStream.EXPLICIT);
      // transmit data
      System.out.println("\nCMS AuthenticatedData demo [parse]:\n");
      System.out.println("Decrypt and verify for the several recipients using their index into the recipientInfos field.");
      parseAuthenticatedDataWithRecipientInfoIndex(false, encodedAuthenticatedData, message);
      System.out.println("Decrypt and verify for the several recipients using their RecipientIdentifier.");
      parseAuthenticatedDataWithRecipientIdentifier(false, encodedAuthenticatedData, message);
      System.out.println("Decrypt and verify for the several recipients using their certificate or kek.");
      parseAuthenticatedDataWithRecipientCertOrKEKId(false, encodedAuthenticatedData, message);
      
      // explict mode; without authenticated attributes
      System.out.println("\nCMS AuthenticatedData demo without authenticated attributes [create, explicit mode]:\n");
      encodedAuthenticatedData = createAuthenticatedData(message,
                                                         macAlgorithm,
                                                         macKeyLength,
                                                         null,
                                                         AuthenticatedDataStream.EXPLICIT);
      // transmit data
      System.out.println("\nCMS AuthenticatedData demo [parse]:\n");
      System.out.println("Decrypt and verify for the several recipients using their index into the recipientInfos field.");
      parseAuthenticatedDataWithRecipientInfoIndex(false, encodedAuthenticatedData, message);
      System.out.println("Decrypt and verify for the several recipients using their RecipientIdentifier.");
      parseAuthenticatedDataWithRecipientIdentifier(false, encodedAuthenticatedData, message);
      System.out.println("Decrypt and verify for the several recipients using their certificate or kek.");
      parseAuthenticatedDataWithRecipientCertOrKEKId(false, encodedAuthenticatedData, message);
      

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

    (new AuthenticatedDataDemo()).start();
    System.out.println("\nReady!");
    System.in.read();
  }
}
