// Copyright (C) 2002 IAIK
// http://jce.iaik.tugraz.at
//
// Copyright (C) 2009 Stiftung Secure Information and 
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
// $Header: /IAIK-CMS/current/src/demo/cms/authEnvelopedData/AuthEnvelopedDataDemo.java 12    23.08.13 14:20 Dbratko $
// $Revision: 12 $
//


package demo.cms.authEnvelopedData;

import iaik.asn1.CodingException;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.cms.AuthEnvelopedData;
import iaik.cms.AuthEnvelopedDataStream;
import iaik.cms.CMSException;
import iaik.cms.CertificateIdentifier;
import iaik.cms.ContentInfo;
import iaik.cms.ContentInfoStream;
import iaik.cms.EncryptedContentInfo;
import iaik.cms.EncryptedContentInfoStream;
import iaik.cms.IssuerAndSerialNumber;
import iaik.cms.KEKIdentifier;
import iaik.cms.KEKRecipientInfo;
import iaik.cms.KeyAgreeRecipientInfo;
import iaik.cms.KeyIdentifier;
import iaik.cms.KeyTransRecipientInfo;
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
 * Demonstrates the usage of class {@link iaik.cms.AuthEnvelopedDataStream} and
 * {@link iaik.cms.AuthEnvelopedData} for authenticated encrypting data using the 
 * CMS type AuthEnvelopedData according to <a href = "http://www.ietf.org/rfc/rfc5083.txt"
 * target="_blank">RFC 5083</a>.
 * <p>
 * This demo uses the AES-CCM and AES-GCM authenticated encryption algorithms
 * as specified by <a href = "http://www.ietf.org/rfc/rfc5084.txt" target="_blank">RFC 5084</a>.
 * The demo creates an AuthEnvelopedData object and subsequently shows several
 * ways that may be used for decrypting the content and verifying the message
 * authentication code for some particular recipient.
 * <br>
 * Since AES-CCM and AES-GCM are not implemented by IAIK-JCE versions prior 3.17, this demo
 * at least may require IAIK-JCE 3.17 as cryptographic service provider. 
 * <p>
 * Keys and certificates are retrieved from the demo KeyStore ("cms.keystore") 
 * which has to be located in your current working directory and may be
 * created by running the {@link demo.keystore.SetupCMSKeyStore
 * SetupCMSKeyStore} program.
 * <p>
 * 
 * @see iaik.cms.AuthEnvelopedDataStream
 * @see iaik.cms.AuthEnvelopedData
 * @see iaik.cms.RecipientInfo
 * @see iaik.cms.KeyTransRecipientInfo
 * @see iaik.cms.KeyAgreeRecipientInfo
 * @see iaik.cms.KEKRecipientInfo
 * 
 * @author Dieter Bratko
 */
public class AuthEnvelopedDataDemo {

  // certificate of rsaUser 1
  X509Certificate rsaUser1;
  // private key of rsaUser 1
  PrivateKey rsaUser1_pk;
  // certificate of rsaUser 2
  X509Certificate rsaUser2;
  // private key of rsaUser 2
  PrivateKey rsaUser2_pk;

  // certificate of esdhUser 1
  X509Certificate esdhUser1;
  // private key of esdhUser 1
  PrivateKey esdhUser1_pk;
  // certificate of esdhUser 2
  X509Certificate esdhUser2;
  // private key of esdhUser 2
  PrivateKey esdhUser2_pk;
  
  // key encryption key for KEKRecipientInfo
  SecretKey kek;
  byte[] kekID;

  // secure random number generator
  SecureRandom random;

  /**
   * Setup the demo certificate chains.
   *
   * Keys and certificates are retrieved from the demo KeyStore ("cms.keystore")
   * file which has to be located in your current working directory and may be
   * created by running {@link demo.keystore.SetupCMSKeyStore
   * SetupCMSKeyStore}.
   *
   * @exception IOException if an file read error occurs
   */
  public AuthEnvelopedDataDemo() throws IOException {
    
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                           AuthEnvelopedDataDemo                                *");
    System.out.println("*        (shows the usage of the CMS AuthEnvelopedData type implementation)      *");
    System.out.println("**********************************************************************************");
    System.out.println();
    
    // add all certificates to the list
    X509Certificate[] certs = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT);
    rsaUser1 = certs[0];
    rsaUser1_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT);
    rsaUser2 = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_)[0];
    rsaUser2_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_);
    
    esdhUser1 = CMSKeyStore.getCertificateChain(CMSKeyStore.ESDH, CMSKeyStore.SZ_1024_CRYPT)[0];
    esdhUser1_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.ESDH, CMSKeyStore.SZ_1024_CRYPT);
    esdhUser2 = CMSKeyStore.getCertificateChain(CMSKeyStore.ESDH, CMSKeyStore.SZ_1024_CRYPT_)[0];
    esdhUser2_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.ESDH, CMSKeyStore.SZ_1024_CRYPT_);
    random = SecRandom.getDefault();
    // create a secret key encryption key for a KEKRecipientInfo
    KeyGenerator kg;
    try {
      kg = KeyGenerator.getInstance("AES");
    } catch (NoSuchAlgorithmException ex) {
      throw new IOException("KeyGenerator for AES not avcailable!");   
    }   
    kg.init(random);
    kek = kg.generateKey();
    kekID = new byte[] { 00, 00, 00, 01 };
  }


  /**
   * Creates a CMS <code>AuthEnvelopedDataStream</code> message.
   *
   * @param message the message to be authenticated-enveloped, as byte representation
   * @param contentAuthEncAlg the id of the content-authenticated encryption algorithm
   * 
   * @return the BER encoding of the <code>AuthEnvelopedData</code> object just created
   * 
   * @exception CMSException if the <code>AuthEnvelopedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createAuthEnvelopedDataStream(byte[] message, 
                                              AlgorithmID contentAuthEncAlg)
    throws CMSException, IOException {

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);
    // create a new AuthEnvelopedData object 
    AuthEnvelopedDataStream authEnvelopedData = new AuthEnvelopedDataStream(is, contentAuthEncAlg);
    
    if (contentAuthEncAlg.equals(AlgorithmID.aes128_CCM) || 
        contentAuthEncAlg.equals(AlgorithmID.aes192_CCM) ||
        contentAuthEncAlg.equals(AlgorithmID.aes256_CCM)) {
      // for aes-ccm we need to know the data input length in advance
      authEnvelopedData.setInputLength(message.length);
    }
    
    //  create some authenticated attributes
    try {
      Attribute[] attributes = { new Attribute(new CMSContentType(ObjectID.cms_data)) };
      authEnvelopedData.setAuthenticatedAttributes(attributes);
    } catch (Exception ex) {
      throw new CMSException("Error creating attribute: " + ex.toString());   
    }

    // create the recipient infos
    RecipientInfo[] recipients = createRecipients();
    // specify the recipients of the encrypted message
    authEnvelopedData.setRecipientInfos(recipients);

    // wrap into ContentInfo
    ContentInfoStream contentInfo = new ContentInfoStream(authEnvelopedData);
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    contentInfo.writeTo(os);
    return os.toByteArray();
  }
  

  /**
   * Decrypts the encrypted content of the given <code>AuthEnvelopedData</code> object for
   * the recipient identified by its index into the recipientInfos field and verifies
   * the message authentication code.
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
   * @param encoding the <code>AuthEnvelopedData</code> object as DER encoded byte array
   * @param key the key to decrypt the message
   * @param recipientInfoIndex the index into the <code>RecipientInfo</code> array
   *                        to which the specified key belongs
   *
   * @return the recovered message, as byte array
   * @exception CMSException if the message cannot be recovered or MAC verification fails
   * @exception IOException if a stream read/write error occurs
   */
  public byte[] getAuthEnvelopedDataStream(byte[] encoding, Key key, int recipientInfoIndex)
    throws CMSException, IOException {

    // create the AuthEnvelopedData object from a BER encoded byte array
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    AuthEnvelopedDataStream authEnvelopedData = new AuthEnvelopedDataStream(is);

    System.out.println("Information about the authenticated encrypted data:");
    EncryptedContentInfoStream eci = authEnvelopedData.getEncryptedContentInfo();
    System.out.println("Content type: "+eci.getContentType().getName());
    System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());

    System.out.println("\nThis message can be decrypted by the owners of the following certificates:");
    RecipientInfo[] recipients = authEnvelopedData.getRecipientInfos();
    
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
    // decrypt the message for the first recipient and verify mac
    try {
      authEnvelopedData.setupCipher(key, recipientInfoIndex);
      InputStream decrypted = authEnvelopedData.getInputStream();
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      Util.copyStream(decrypted, os, null);
      byte[] content = os.toByteArray();

      // get authenticated attributes
      Attribute contentTypeAttribute = authEnvelopedData.getAuthenticatedAttribute(ObjectID.contentType);
      if (contentTypeAttribute != null) {
        CMSContentType contentType = (CMSContentType)contentTypeAttribute.getAttributeValue();
        System.out.println("Authenticated content type attribute included: " + contentType.get().getName());
      }
      
      return content;
    } catch (InvalidKeyException ex) {
      throw new CMSException("Private key error: "+ex.toString());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.toString());
    } catch (CodingException ex) {
      throw new CMSException("Error reading authenticated attributes: "+ex.toString());
    }
  }
  
  /**
   * Decrypts the encrypted content of the given <code>EnvelopedData</code> object for
   * the recipient identified by recipient identifier and verifies the message 
   * authentication code.
   * <p>
   * This way of decrypting the content may be used for any type of RecipientInfo
   * (KeyTransRecipientInfo, KeyAgreeRecipientInfo, KEKRecipientInfo). The 
   * recipient in mind is identified by its recipient identifier.
   *
   * @param encoding the <code>AuthEnvelopedData</code> object as BER encoded byte array
   * @param key the key to decrypt the message
   * @param recipientID the recipient identifier uniquely identifying the key of the
   *        recipient
   *
   * @return the recovered message, as byte array
   * @exception CMSException if the message cannot be recovered
   * @exception IOException if a stream read/write error occurs
   */
  public byte[] getAuthEnvelopedDataStream(byte[] encoding, Key key, KeyIdentifier recipientID)
    throws CMSException, IOException {

    // create the AuthEnvelopedData object from a DER encoded byte array
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    AuthEnvelopedDataStream authEnvelopedData = new AuthEnvelopedDataStream(is);

    System.out.println("Information about the encrypted data:");
    EncryptedContentInfoStream eci = authEnvelopedData.getEncryptedContentInfo();
    System.out.println("Content type: "+eci.getContentType().getName());
    System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());
    
    // get the right RecipientInfo
    System.out.println("\nSearch for RecipientInfo:");
    RecipientInfo recipient = authEnvelopedData.getRecipientInfo(recipientID);
    if (recipient != null) {
      System.out.println("RecipientInfo: " + recipient);   
    } else {
      throw new CMSException("No recipient with ID: " + recipientID);
    }    
    // decrypt the content encryption key and the content; verify mac
    try {
      System.out.println("Decrypt encrypted content encryption key...");
      SecretKey cek = recipient.decryptKey(key, recipientID);
      System.out.println("Decrypt content with decrypted content encryption key...");
      authEnvelopedData.setupCipher(cek);
      InputStream decrypted = authEnvelopedData.getInputStream();
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      Util.copyStream(decrypted, os, null);
      byte[] content = os.toByteArray();

      // get authenticated attributes
      Attribute contentTypeAttribute = authEnvelopedData.getAuthenticatedAttribute(ObjectID.contentType);
      if (contentTypeAttribute != null) {
        CMSContentType contentType = (CMSContentType)contentTypeAttribute.getAttributeValue();
        System.out.println("Authenticated content type attribute included: " + contentType.get().getName());
      }
      
      return content;
    } catch (InvalidKeyException ex) {
      throw new CMSException("Private key error: "+ex.toString());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.toString());
    } catch (CodingException ex) {
      throw new CMSException("Error reading authenticated attributes: "+ex.toString());
    }
  }
  
  /**
   * Decrypts the encrypted content of the given <code>AuthEnvelopedData</code> object for
   * the recipient identified by its recipient certificate or kekID and verifies the message 
   * authentication code.
   * <p>
   * Since recipient certificates only may be used for for RecipientInfos of type
   * KeyTransRecipientInfo or KeyAgreeRecipientInfo, a key id has to be supplied
   * for decrypting the content for a recipient using a KEKRecipientInfo.
   *
   * @param encoding the <code>AuthEnvelopedData</code> object as BER encoded byte array
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
  public byte[] getAuthEnvelopedDataStream(byte[] encoding, Key key, X509Certificate recipientCert, byte[] kekID)
    throws CMSException, IOException {

    // create the AuthEnvelopedData object from a BER encoded byte array
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    AuthEnvelopedDataStream authEnvelopedData = new AuthEnvelopedDataStream(is);

    System.out.println("Information about the encrypted data:");
    EncryptedContentInfoStream eci = (EncryptedContentInfoStream)authEnvelopedData.getEncryptedContentInfo();
    System.out.println("Content type: "+eci.getContentType().getName());
    System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());
    
    // decrypt the content encryption key and the content; verify mac
    try {
      System.out.println("Decrypt the content...");
      if (recipientCert != null) {
        authEnvelopedData.setupCipher(key, recipientCert);
      } else {
        // KEKRecipientInfo
        authEnvelopedData.setupCipher(key, new KEKIdentifier(kekID));
      }  
      InputStream decrypted = authEnvelopedData.getInputStream();
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      Util.copyStream(decrypted, os, null);
      byte[] content = os.toByteArray();

      // get authenticated attributes
      Attribute contentTypeAttribute = authEnvelopedData.getAuthenticatedAttribute(ObjectID.contentType);
      if (contentTypeAttribute != null) {
        CMSContentType contentType = (CMSContentType)contentTypeAttribute.getAttributeValue();
        System.out.println("Authenticated content type attribute included: " + contentType.get().getName());
      }
      
      return content;
    } catch (InvalidKeyException ex) {
      throw new CMSException("Private key error: "+ex.toString());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.toString());
    } catch (CodingException ex) {
      throw new CMSException("Error reading authenticated attributes: "+ex.toString());
    }
  }


  // non stream

  /**
   * Creates a CMS <code>AuthEnvelopedData</code> message.
   * 
   * @param message the message to be enveloped, as byte representation
   * @param contentAuthEncAlg the id of the content-authenticated encryption algorithm
   *
   * 
   * @return the encoded <code>AuthEnvelopedData</code>, as byte array
   * 
   * @exception CMSException if the <code>AuthEnvelopedData</code> object cannot
   *                          be created
   */
  public byte[] createAuthEnvelopedData(byte[] message, AlgorithmID contentAuthEncAlg)
    throws CMSException {
    
    AuthEnvelopedData authEnvelopedData;

    // create a new AuthEnvelopedData object
    authEnvelopedData = new AuthEnvelopedData(message, contentAuthEncAlg);
    
    //  create some authenticated attributes
    try {
      Attribute[] attributes = { new Attribute(new CMSContentType(ObjectID.cms_data)) };
      authEnvelopedData.setAuthenticatedAttributes(attributes);
    } catch (Exception ex) {
      throw new CMSException("Error creating attribute: " + ex.toString());   
    }
    
    // set the RecipientInfos
    RecipientInfo[] recipients = createRecipients();
    authEnvelopedData.setRecipientInfos(recipients);

    // wrap into ContentInfo
    ContentInfo contentInfo = new ContentInfo(authEnvelopedData);
    // return encoded EnvelopedData
    return contentInfo.getEncoded();
  }


  /**
   * Decrypts the encrypted content of the given <code>AuthEnvelopedData</code> object for
   * the recipient identified by its index into the recipientInfos field and verifies
   * the message authentication code.
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
   * @param enc the encoded <code>AuthEnvelopedData</code>
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
  public byte[] getAuthEnvelopedData(byte[] enc, Key key, int recipientInfoIndex) 
    throws CMSException, IOException {
    ByteArrayInputStream bais = new ByteArrayInputStream(enc);
    AuthEnvelopedData authEnvelopedData = new AuthEnvelopedData(bais);

    System.out.println("Information about the encrypted data:");
    EncryptedContentInfo eci = (EncryptedContentInfo)authEnvelopedData.getEncryptedContentInfo();
    System.out.println("Content type: "+eci.getContentType().getName());
    System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());

    System.out.println("\nThis message can be decrypted by the owners of the following certificates:");
    RecipientInfo[] recipients = authEnvelopedData.getRecipientInfos();
    
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
    
    // decrypt the message and verify the mac
    try {
      authEnvelopedData.setupCipher(key, recipientInfoIndex);
      byte[] content = authEnvelopedData.getContent();

      // get authenticated attributes
      Attribute contentTypeAttribute = authEnvelopedData.getAuthenticatedAttribute(ObjectID.contentType);
      if (contentTypeAttribute != null) {
        CMSContentType contentType = (CMSContentType)contentTypeAttribute.getAttributeValue();
        System.out.println("Authenticated content type attribute included: " + contentType.get().getName());
      }
      
      return content;
    } catch (InvalidKeyException ex) {
      throw new CMSException("Private key error: "+ex.toString());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.toString());
    } catch (CodingException ex) {
      throw new CMSException("Error reading authenticated attributes: "+ex.toString());
    }
  }
  
  /**
   * Decrypts the encrypted content of the given <code>AuthEnvelopedData</code> object for
   * the recipient identified by recipient identifier.
   * <p>
   * This way of decrypting the content may be used for any type of RecipientInfo
   * (KeyTransRecipientInfo, KeyAgreeRecipientInfo, KEKRecipientInfo). The 
   * recipient in mind is identified by its recipient identifier.
   *
   * @param enc the BER encoded <code>AuthEnvelopedData</code> ASN.1 object
   * @param key the key to decrypt the message
   * @param recipientID the recipient identifier uniquely identifying the key of the
   *        recipient
   *
   * @return the recovered message, as byte array
   * @exception CMSException if the message cannot be recovered
   * @exception IOException if an I/O error occurs
   */
  public byte[] getAuthEnvelopedData(byte[] enc, Key key, KeyIdentifier recipientID) 
    throws CMSException, IOException {
    ByteArrayInputStream bais = new ByteArrayInputStream(enc);
    AuthEnvelopedData authEnvelopedData = new AuthEnvelopedData(bais);

    System.out.println("Information about the encrypted data:");
    EncryptedContentInfo eci = (EncryptedContentInfo)authEnvelopedData.getEncryptedContentInfo();
    System.out.println("Content type: "+eci.getContentType().getName());
    System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());

    // get the right RecipientInfo
    System.out.println("\nSearch for RecipientInfo:");
    RecipientInfo recipient = authEnvelopedData.getRecipientInfo(recipientID);
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
      // decrypt content and verify mac      
      authEnvelopedData.setupCipher(cek);
      byte[] content = authEnvelopedData.getContent();

      // get authenticated attributes
      Attribute contentTypeAttribute = authEnvelopedData.getAuthenticatedAttribute(ObjectID.contentType);
      if (contentTypeAttribute != null) {
        CMSContentType contentType = (CMSContentType)contentTypeAttribute.getAttributeValue();
        System.out.println("Authenticated content type attribute included: " + contentType.get().getName());
      }
      
      return content;
    } catch (InvalidKeyException ex) {
      throw new CMSException("Private key error: "+ex.toString());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.toString());
    } catch (CodingException ex) {
      throw new CMSException("Error reading authenticated attributes: "+ex.toString());
    }
  }
  
  /**
   * Decrypts the encrypted content of the given <code>AuthEnvelopedData</code> object for
   * the recipient identified by its recipient certificate or keyID.
   * <p>
   * Since recipient certificates only may be used for for RecipientInfos of type
   * KeyTransRecipientInfo or KeyAgreeRecipientInfo, a key id has to be supplied
   * for decrypting the content for a recipient using a KEKRecipientInfo.
   *
   * @param enc the BER encoded <code>AuthEnvelopedData</code> ASN.1 object
   * @param key the key to decrypt the message
   * @param recipientCert the certificate of the recipient having a RecipientInfo of
   *                      type KeyTransRecipientInfo or KeyAgreeRecipientInfo
   * @param kekID the kekID identifying the recipient key when using a RecipientInfo
   *              of type KEKRecipientInfo
   *
   * @return the recovered message, as byte array
   * @exception CMSException if the message cannot be recovered
   */
  public byte[] getAuthEnvelopedData(byte[] enc, Key key, X509Certificate recipientCert, byte[] kekID) 
    throws CMSException, IOException {
    ByteArrayInputStream bais = new ByteArrayInputStream(enc);
    AuthEnvelopedData authEnvelopedData = new AuthEnvelopedData(bais);

    System.out.println("Information about the encrypted data:");
    EncryptedContentInfo eci = (EncryptedContentInfo)authEnvelopedData.getEncryptedContentInfo();
    System.out.println("Content type: "+eci.getContentType().getName());
    System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());

    // decrypt the content encryption key and the content
    try {
      System.out.println("Decrypt the content and verify mac...");
      // decrypt content and verify mac
      if (recipientCert != null) {
        authEnvelopedData.setupCipher(key, recipientCert);
      } else {
        // KEKRecipientInfo
        authEnvelopedData.setupCipher(key, new KEKIdentifier(kekID));
      }
      
      byte[] content = authEnvelopedData.getContent();

      // get authenticated attributes
      Attribute contentTypeAttribute = authEnvelopedData.getAuthenticatedAttribute(ObjectID.contentType);
      if (contentTypeAttribute != null) {
        CMSContentType contentType = (CMSContentType)contentTypeAttribute.getAttributeValue();
        System.out.println("Authenticated content type attribute included: " + contentType.get().getName());
      }
      
      return content;
    } catch (InvalidKeyException ex) {
      throw new CMSException("Private key error: "+ex.toString());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.toString());
    } catch (CodingException ex) {
      throw new CMSException("Error reading authenticated attributes: "+ex.toString());
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
      recipients[0] = new KeyTransRecipientInfo(rsaUser1, 
                                                (AlgorithmID)AlgorithmID.rsaEncryption.clone());
      // rsaUser2 is the second receiver (cert identifief by SubjectKeyIdentifier)
      recipients[1] = new KeyTransRecipientInfo(rsaUser2, 
                                                CertificateIdentifier.SUBJECT_KEY_IDENTIFIER, 
                                                (AlgorithmID)AlgorithmID.rsaEncryption.clone());

      // next recipients use key agreement
      // the key encryption (key agreement) algorithm to use:
      AlgorithmID keyEA = (AlgorithmID)AlgorithmID.esdhKeyAgreement.clone();
      // the key wrap algorithm to use:
      AlgorithmID keyWrapAlg = (AlgorithmID)AlgorithmID.cms_aes128_wrap.clone();
      // the length of the key encryption key to be generated:
      int kekLength = 128;
      recipients[2] = new KeyAgreeRecipientInfo(keyEA, keyWrapAlg, kekLength);
      // esdhUser1 is the third receiver  (cert identified by IssuerAndSerialNumber)
      ((KeyAgreeRecipientInfo)recipients[2]).addRecipient(esdhUser1, CertificateIdentifier.ISSUER_AND_SERIALNUMBER);
      // esdhUser2 is the fourth receiver (cert identified by RecipientKeyIdentifier)
      ((KeyAgreeRecipientInfo)recipients[2]).addRecipient(esdhUser2, CertificateIdentifier.RECIPIENT_KEY_IDENTIFIER);
      
      // last receiver uses a symmetric key encryption key  
      AlgorithmID kea = (AlgorithmID)AlgorithmID.cms_aes128_wrap.clone();
      KEKIdentifier kekIdentifier = new KEKIdentifier(kekID);
      recipients[3] = new KEKRecipientInfo(kekIdentifier, kea, kek);
    } catch (Exception ex) {
      throw new CMSException("Error adding recipients: " + ex.getMessage()); 
    }    
    return recipients;
  }  
  
  /**
   * Parses an AuthEnvelopedData and decrypts the content for all test recipients
   * using the index into the recipientInfos field for identifying the recipient.
   *
   * @param stream whether to use AuthEnvelopedDataStream or AuthEnvelopedData
   * @param encodedAuthEnvelopedData the encoded AuthEnvelopedData object 
   *
   * @exception Exception if some error occurs during decoding/decryption
   */ 
  public void parseAuthEnvelopedDataWithRecipientInfoIndex(boolean stream, byte[] encodedAuthEnvelopedData) throws Exception {
    byte[] receivedMessage;
    if (stream) {
      // rsaUser1
      System.out.println("\nDecrypt for rsaUser1:");
      receivedMessage = getAuthEnvelopedDataStream(encodedAuthEnvelopedData, rsaUser1_pk, 0);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // rsaUser2
      System.out.println("\nDecrypt for rsaUser2:");
      receivedMessage = getAuthEnvelopedDataStream(encodedAuthEnvelopedData, rsaUser2_pk, 1);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // esdhUser1
      System.out.println("\nDecrypt for esdhUser1:");
      receivedMessage = getAuthEnvelopedDataStream(encodedAuthEnvelopedData, esdhUser1_pk, 2);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // esdhUser2
      System.out.println("\nDecrypt for esdhUser2:");
      receivedMessage = getAuthEnvelopedDataStream(encodedAuthEnvelopedData, esdhUser2_pk, 2);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // kekUser
      System.out.println("\nDecrypt for kekUser:");
      receivedMessage = getAuthEnvelopedDataStream(encodedAuthEnvelopedData, kek, 3);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
    } else {
      // rsaUser1
      System.out.println("\nDecrypt for rsaUser1:");
      receivedMessage = getAuthEnvelopedData(encodedAuthEnvelopedData, rsaUser1_pk, 0);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
       // rsaUser2
      System.out.println("\nDecrypt for rsaUser2:");
      receivedMessage = getAuthEnvelopedData(encodedAuthEnvelopedData, rsaUser2_pk, 1);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // esdhUser1
      System.out.println("\nDecrypt for esdhUser1:");
      receivedMessage = getAuthEnvelopedData(encodedAuthEnvelopedData, esdhUser1_pk, 2);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // esdhUser2
      System.out.println("\nDecrypt for esdhUser2:");
      receivedMessage = getAuthEnvelopedData(encodedAuthEnvelopedData, esdhUser2_pk, 2);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // kekUser
      System.out.println("\nDecrypt for kekUser:");
      receivedMessage = getAuthEnvelopedData(encodedAuthEnvelopedData, kek, 3);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
    }    
  }
  
  /**
   * Parses an AuthEnvelopedData and decrypts the content for all test recipients
   * using their recipient identifiers for identifying the recipient.
   *
   * @param stream whether to use AuthEnvelopedDataStream or AuthEnvelopedData
   * @param encodedAuthEnvelopedData the encoded AuthEnvelopedData object 
   *
   * @exception Exception if some error occurs during decoding/decryption
   */ 
  public void parseAuthEnvelopedDataWithRecipientIdentifier(boolean stream, byte[] encodedAuthEnvelopedData) throws Exception {
    byte[] receivedMessage;
    if (stream) {
      // rsaUser1
      System.out.println("\nDecrypt for rsaUser1:");
      receivedMessage = getAuthEnvelopedDataStream(encodedAuthEnvelopedData, rsaUser1_pk, new IssuerAndSerialNumber(rsaUser1));
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // rsaUser2
      System.out.println("\nDecrypt for rsaUser2:");
      receivedMessage = getAuthEnvelopedDataStream(encodedAuthEnvelopedData, rsaUser2_pk, new SubjectKeyID(rsaUser2));
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // esdhUser1
      System.out.println("\nDecrypt for esdhUser1:");
      receivedMessage = getAuthEnvelopedDataStream(encodedAuthEnvelopedData, esdhUser1_pk, new IssuerAndSerialNumber(esdhUser1));
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // esdhUser2
      System.out.println("\nDecrypt for esdhUser2:");
      receivedMessage = getAuthEnvelopedDataStream(encodedAuthEnvelopedData, esdhUser2_pk, new RecipientKeyIdentifier(esdhUser2));
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // kekUser
      System.out.println("\nDecrypt for kekUser:");
      receivedMessage = getAuthEnvelopedDataStream(encodedAuthEnvelopedData, kek, new KEKIdentifier(kekID));
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
    } else {
      // rsaUser1
      System.out.println("\nDecrypt for rsaUser1:");
      receivedMessage = getAuthEnvelopedData(encodedAuthEnvelopedData, rsaUser1_pk, new IssuerAndSerialNumber(rsaUser1));
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
       // rsaUser2
      System.out.println("\nDecrypt for rsaUser2:");
      receivedMessage = getAuthEnvelopedData(encodedAuthEnvelopedData, rsaUser2_pk, new SubjectKeyID(rsaUser2));
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // esdhUser1
      System.out.println("\nDecrypt for esdhUser1:");
      receivedMessage = getAuthEnvelopedData(encodedAuthEnvelopedData, esdhUser1_pk, new IssuerAndSerialNumber(esdhUser1));
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // esdhUser2
      System.out.println("\nDecrypt for esdhUser2:");
      receivedMessage = getAuthEnvelopedData(encodedAuthEnvelopedData, esdhUser2_pk, new RecipientKeyIdentifier(esdhUser2));
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // kekUser
      System.out.println("\nDecrypt for kekUser:");
      receivedMessage = getAuthEnvelopedData(encodedAuthEnvelopedData, kek, new KEKIdentifier(kekID));
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
    }    
  }
  
  /**
   * Parses an AuthEnvelopedData and decrypts the content for all test recipients
   * using their recipient certificate (for RecipientInfos of type KeyTransRecipientInfo
   * or KeyAgreeRecipientInfo) or key id (for RecipientInfos of type KEKRecipientInfo)
   * for identifying the recipient.
   *
   * @param stream whether to use AuthEnvelopedDataStream or AuthEnvelopedData
   * @param encodedAuthEnvelopedData the encoded AuthEnvelopedData object 
   *
   * @exception Exception if some error occurs during decoding/decryption
   */ 
  public void parseAuthEnvelopedDataWithRecipientCertOrKEKId(boolean stream, byte[] encodedAuthEnvelopedData) throws Exception {
    byte[] receivedMessage;
    if (stream) {
      // rsaUser1
      System.out.println("\nDecrypt for rsaUser1:");
      receivedMessage = getAuthEnvelopedDataStream(encodedAuthEnvelopedData, rsaUser1_pk, rsaUser1, null);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // rsaUser2
      System.out.println("\nDecrypt for rsaUser2:");
      receivedMessage = getAuthEnvelopedDataStream(encodedAuthEnvelopedData, rsaUser2_pk, rsaUser2, null);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // esdhUser1
      System.out.println("\nDecrypt for esdhUser1:");
      receivedMessage = getAuthEnvelopedDataStream(encodedAuthEnvelopedData, esdhUser1_pk, esdhUser1, null);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // esdhUser2
      System.out.println("\nDecrypt for esdhUser2:");
      receivedMessage = getAuthEnvelopedDataStream(encodedAuthEnvelopedData, esdhUser2_pk, esdhUser2, null);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // kekUser
      System.out.println("\nDecrypt for kekUser:");
      receivedMessage = getAuthEnvelopedDataStream(encodedAuthEnvelopedData, kek, null, kekID);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
    } else {
      // rsaUser1
      System.out.println("\nDecrypt for rsaUser1:");
      receivedMessage = getAuthEnvelopedData(encodedAuthEnvelopedData, rsaUser1_pk, rsaUser1, null);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
       // rsaUser2
      System.out.println("\nDecrypt for rsaUser2:");
      receivedMessage = getAuthEnvelopedData(encodedAuthEnvelopedData, rsaUser2_pk, rsaUser2, null);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // esdhUser1
      System.out.println("\nDecrypt for esdhUser1:");
      receivedMessage = getAuthEnvelopedData(encodedAuthEnvelopedData, esdhUser1_pk, esdhUser1, null);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // esdhUser2
      System.out.println("\nDecrypt for esdhUser2:");
      receivedMessage = getAuthEnvelopedData(encodedAuthEnvelopedData, esdhUser2_pk, esdhUser2, null);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
      // kekUser
      System.out.println("\nDecrypt for kekUser:");
      receivedMessage = getAuthEnvelopedData(encodedAuthEnvelopedData, kek, null, kekID);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(receivedMessage));
    }    
  }
  
  /**
   * Starts the test.
   */
  public void start() {
    // AES-CCM
    AlgorithmID contentAuthEncAlg = (AlgorithmID)AlgorithmID.aes128_CCM.clone();
    start(contentAuthEncAlg);
    
    // AES-GCM
    contentAuthEncAlg = (AlgorithmID)AlgorithmID.aes128_GCM.clone();
    start(contentAuthEncAlg);
  }
  
  /**
   * Starts the test for the given content-authenticated encryption algorithm.
   * 
   * @param contentAuthEncAlg the id of the content-authenticated encryption algorithm
   */
  public void start(AlgorithmID contentAuthEncAlg) {
     // the test message
    String m = "This is the test message.";
    System.out.println("Test message: \""+m+"\"");
    System.out.println();
    byte[] message = m.getBytes();

    try {
      byte[] encodedAuthEnvelopedData;
      System.out.println("Stream implementation demos");
      System.out.println("===========================");

      
      
      // the stream implementation
      //
      // test CMS AuthEnvelopedDataStream
      //
      System.out.println("\nCMS AuthEnvelopedDataStream demo [create]:\n");
      encodedAuthEnvelopedData = createAuthEnvelopedDataStream(message, (AlgorithmID)contentAuthEncAlg.clone());
      // transmit data
      System.out.println("\nCMS AuthEnvelopedDataStream demo [parse]:\n");
      System.out.println("Decrypt for the several recipients using their index into the recipientInfos field.");
      parseAuthEnvelopedDataWithRecipientInfoIndex(true, encodedAuthEnvelopedData);
      System.out.println("Decrypt for the several recipients using their RecipientIdentifier.");
      parseAuthEnvelopedDataWithRecipientIdentifier(true, encodedAuthEnvelopedData);
      System.out.println("Decrypt for the several recipients using their certificate or symmetric kek.");
      parseAuthEnvelopedDataWithRecipientCertOrKEKId(true, encodedAuthEnvelopedData);

      // the non-stream implementation
      System.out.println("\nNon-stream implementation demos");
      System.out.println("===============================");

            
      //
      // test CMS AuthEnvelopedData
      //
      System.out.println("\nCMS AutjEnvelopedData demo [create]:\n");
      encodedAuthEnvelopedData = createAuthEnvelopedData(message, (AlgorithmID)contentAuthEncAlg.clone());
      // transmit data
      System.out.println("\nCMS AuthEnvelopedData demo [parse]:\n");
      System.out.println("Decrypt for the several recipients using their index into the recipientInfos field.");
      parseAuthEnvelopedDataWithRecipientInfoIndex(false, encodedAuthEnvelopedData);
      System.out.println("Decrypt for the several recipients using their RecipientIdentifier.");
      parseAuthEnvelopedDataWithRecipientIdentifier(false, encodedAuthEnvelopedData);
      System.out.println("Decrypt for the several recipients using their certificate or symmetric kek.");
      parseAuthEnvelopedDataWithRecipientCertOrKEKId(false, encodedAuthEnvelopedData);
      

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

    (new AuthEnvelopedDataDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
