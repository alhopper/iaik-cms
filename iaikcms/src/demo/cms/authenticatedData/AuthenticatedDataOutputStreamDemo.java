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
// $Header: /IAIK-CMS/current/src/demo/cms/authenticatedData/AuthenticatedDataOutputStreamDemo.java 9     23.08.13 14:19 Dbratko $
// $Revision: 9 $demo.cms.authenticatedData
package demo.cms.authenticatedData;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.cms.AuthenticatedDataOutputStream;
import iaik.cms.AuthenticatedDataStream;
import iaik.cms.CMSAlgorithmID;
import iaik.cms.CMSException;
import iaik.cms.CertificateIdentifier;
import iaik.cms.ContentInfoOutputStream;
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
 * Demonstrates the usage of class {@link iaik.cms.AuthenticatedDataOutputStream} and
 * {@link iaik.cms.AuthenticatedDataOutputStream} for recipient-specific protecting the 
 * integrity of message using the CMS type AuthenticatedData.
 * <p>
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
 * @see iaik.cms.AuthenticatedDataStream
 * @see iaik.cms.AuthenticatedDataOutputStream
 * 
 * @author Dieter Bratko
 */
public class AuthenticatedDataOutputStreamDemo {
  
  // certificate of rsaUser 1
  X509Certificate rsaUser1;
  // private key of rsaUser 1
  PrivateKey rsaUser1_pk;
  // certificate of rsaUser 2
  X509Certificate rsaUser2;
  // private key of rsaUser 2
  PrivateKey rsaUser2_pk;

  // certificate of (originator) SSDH User 1 (static-static Diffie-Hellman)
  X509Certificate ssdhUser1;
  X509Certificate[] originatorCerts;
  // private key of SSDH User 1
  PrivateKey ssdhUser1_pk;
  // certificate of SSDH User 2 (static-static Diffie-Hellman)
  X509Certificate ssdhUser2;
  // private key of SSDH User 2
  PrivateKey ssdhUser2_pk;
  
  // key encryption key for KEKRecipientInfo
  SecretKey kek;
  byte[] kekID;

  
  // secure random number generator
  SecureRandom random;

  /**
   * Setup the demo certificate chains.
   *
   * Keys and certificate are retrieved from the demo KeyStore which
   * has to be located in your current working directory and may be
   * created by running {@link demo.keystore.SetupCMSKeyStore
   * SetupCMSKeyStore}.
   *
   * @exception IOException if an file read error occurs
   */
  public AuthenticatedDataOutputStreamDemo() throws IOException {
    
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                        AuthenticatedDataOutputStream demo                      *");
    System.out.println("*   (shows the usage of the CMS AuthenticatedDataOutputStream implementation)    *");
    System.out.println("**********************************************************************************");
    System.out.println();
    
    // add all certificates to the list
    rsaUser1 = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT)[0];
    rsaUser1_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT);
    rsaUser2 = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_)[0];
    rsaUser2_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_);
    
    originatorCerts = CMSKeyStore.getCertificateChain(CMSKeyStore.SSDH, CMSKeyStore.SZ_1024_CRYPT);
    ssdhUser1 = originatorCerts[0];
    ssdhUser1_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.SSDH, CMSKeyStore.SZ_1024_CRYPT);
    ssdhUser2 = CMSKeyStore.getCertificateChain(CMSKeyStore.SSDH, CMSKeyStore.SZ_1024_CRYPT_)[0];
    ssdhUser2_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.SSDH, CMSKeyStore.SZ_1024_CRYPT_);
    
    random = SecRandom.getDefault();
    
    //  create a secret key encryption key for a KEKRecipientInfo
    KeyGenerator kg;
    try {
      kg = KeyGenerator.getInstance("3DES");
    } catch (NoSuchAlgorithmException ex) {
      throw new IOException("KeyGenerator for 3DES not avcailable!");   
    }   
    kg.init(random);
    kek = kg.generateKey();
    kekID = new byte[] { 00, 00, 00, 01 };
    
  }


  /**
   * Creates a CMS <code>AuthenticatedDataOutputStream</code> for the given message message.
   *
   * @param message the message to be authenticated, as byte representation
   * @param macAlgorithm the mac algorithm to be used
   * @param macKeyLength the length of the temporary MAC key to be generated
   * @param digestAlgorithm the digest algorithm to be used to calculate a digest
   *                        from the content if authenticated attributes should
   *                        be included
   * @return the BER encoding of the <code>AuthenticatedData</code> object just created,
   *         wrapped into a ContentInfo
   * 
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
    
    AuthenticatedDataOutputStream authenticatedData;

    //  a stream from which to read the data to be authenticated
    ByteArrayInputStream is = new ByteArrayInputStream(message);
    
    // the stream to which to write the AuthenticatedData
    ByteArrayOutputStream resultStream = new ByteArrayOutputStream();

    //  wrap AuthenticatedData into a ContentInfo 
    ContentInfoOutputStream contentInfoStream = 
      new ContentInfoOutputStream(ObjectID.cms_authData, resultStream);

    // create AuthenticatedDataOutputStream 
    try {
      authenticatedData = new AuthenticatedDataOutputStream(contentType,
                                                            contentInfoStream, 
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
    originator.setCertificates(originatorCerts);
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
    
    int blockSize = 20; // in real world we would use a block size like 2048
    //  write in the data to be signed
    byte[] buffer = new byte[blockSize];
    int bytesRead;
    while ((bytesRead = is.read(buffer)) != -1) {
      authenticatedData.write(buffer, 0, bytesRead);
    }
    
    // closing the stream adds auth/unauth attributes, calculates and adds the mac value, . 
    authenticatedData.close();
    return resultStream.toByteArray();
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

    // parse the BER encoded AuthenticatedData
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
   * This way of decrypting the encrypted mac key may be used for any type of RecipientInfo
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

    // parse the BER encoded AuthenticatedData 
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
   * @return the verified message, as byte array
   * 
   * @exception CMSException if the authenticated data cannot be verified
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
      recipients[0] = new KeyTransRecipientInfo(rsaUser1, 
                                                (AlgorithmID)AlgorithmID.rsaEncryption.clone());
      // rsaUser2 is the second receiver (cert identifief by SubjectKeyIdentifier)
      recipients[1] = new KeyTransRecipientInfo(rsaUser2,
                                                CertificateIdentifier.SUBJECT_KEY_IDENTIFIER,
                                                (AlgorithmID)AlgorithmID.rsaEncryption.clone());
      
      // next recipients use key agreement (Static-Static Diffie-Hellman)
      // the key encryption (key agreement) algorithm to use:
      AlgorithmID keyEA = (AlgorithmID)AlgorithmID.ssdhKeyAgreement.clone();
      // the key wrap algorithm to use:
      AlgorithmID keyWrapAlg = (AlgorithmID)CMSAlgorithmID.cms_HMACwith3DES_wrap.clone();
      // the length of the key encryption key to be generated:
      int kekLength = 192;
      // in static-static mode we may supply user keying material
      byte[] ukm = new byte[64];
      random.nextBytes(ukm);
      // ssdhUser1 is originator
      recipients[2] = new KeyAgreeRecipientInfo(ssdhUser1, 
                                                ssdhUser1_pk,
                                                KeyIdentifier.ISSUER_AND_SERIALNUMBER,
                                                keyEA, 
                                                keyWrapAlg, 
                                                kekLength, 
                                                ukm);
      // add ssdhUser1 (originator) as recipient, too
      ((KeyAgreeRecipientInfo)recipients[2]).addRecipient(ssdhUser1, CertificateIdentifier.ISSUER_AND_SERIALNUMBER);
      // ssdhUser2 is the recipient (cert identified by RecipientKeyIdentifier)
      ((KeyAgreeRecipientInfo)recipients[2]).addRecipient(ssdhUser2, CertificateIdentifier.RECIPIENT_KEY_IDENTIFIER);

      // last receiver uses a symmetric key encryption key  
      AlgorithmID kea = (AlgorithmID)CMSAlgorithmID.cms_HMACwith3DES_wrap.clone();
      KEKIdentifier kekIdentifier = new KEKIdentifier(kekID);
      recipients[3] = new KEKRecipientInfo(kekIdentifier, kea, kek);
      
    } catch (Exception ex) {
      throw new CMSException("Error adding recipients: " + ex.getMessage()); 
    }    
    return recipients;
  }  
  
  /**
   * Parses an AuthenticatedData, decrypts the mac keys for all test recipients
   * using the index into the recipientInfos field for identifying the recipient
   * and verifies the content mac.
   *
   * @param encodedAuthenticatedData the encoded AuthenticatedData object 
   *
   * @exception Exception if some error occurs during mac key decryption / mac verification
   */ 
  public void parseAuthenticatedDataWithRecipientInfoIndex(byte[] encodedAuthenticatedData,
                                                           byte[] message) 
    throws Exception {
    
    byte[] received_message;
    
    // rsaUser1
    System.out.println("\nVerify MAC for rsaUser1:");
    
    received_message = getAuthenticatedDataStream(encodedAuthenticatedData, 
                                                  message,
                                                  rsaUser1_pk,
                                                  0);
    System.out.print("\nContent: ");
    System.out.println(new String(received_message));
      
    // rsaUser2
    System.out.println("\nVerify MAC for rsaUser2:");
    received_message = getAuthenticatedDataStream(encodedAuthenticatedData, 
                                                  message,
                                                  rsaUser2_pk,
                                                  1);
    
    // ssdhUser1
    System.out.println("\nVerify MAC for ssdhUser1:");
    
    received_message = getAuthenticatedDataStream(encodedAuthenticatedData, 
                                                  message,
                                                  ssdhUser1_pk,
                                                  2);
    System.out.print("\nContent: ");
    System.out.println(new String(received_message));
      
    // ssdhUser2
    System.out.println("\nVerify MAC for ssdhUser2:");
    received_message = getAuthenticatedDataStream(encodedAuthenticatedData, 
                                                  message,
                                                  ssdhUser2_pk,
                                                  2);
    
    // kekUser
    System.out.println("\nVerify MAC for kekUser:");
    received_message = getAuthenticatedDataStream(encodedAuthenticatedData,
                                                  message,
                                                  kek,
                                                  3);
    System.out.print("\nContent: ");
    System.out.println(new String(received_message));
  }
  
  /**
   * Parses an AuthenticatedData, decrypts the mac keys for all test recipients
   * using their recipient identifiers for identifying the recipient
   * and verifies the content mac.
   *
   * @param encodedAuthenticatedData the encoded AuthenticatedData object 
   *
   * @exception Exception if some error occurs during mac key decryption / mac verification
   */ 
  public void parseAuthenticatedDataWithRecipientIdentifier(byte[] encodedAuthenticatedData,
                                                            byte[] message) 
    throws Exception {
        
    byte[] received_message;
    
    //  rsaUser1
    System.out.println("\nVerify MAC for rsaUser1:");
    received_message = getAuthenticatedDataStream(encodedAuthenticatedData, 
                                                  message, 
                                                  rsaUser1_pk, 
                                                  new IssuerAndSerialNumber(rsaUser1));
    System.out.print("\nContent: ");
    System.out.println(new String(received_message));
    
    // rsaUser2
    System.out.println("\nVerify MAC for rsaUser2:");
    received_message = getAuthenticatedDataStream(encodedAuthenticatedData,
                                                  message,
                                                  rsaUser2_pk, 
                                                  new SubjectKeyID(rsaUser2));

    // ssdhUser1
    System.out.println("\nVerify MAC for ssdhUser1:");
    received_message = getAuthenticatedDataStream(encodedAuthenticatedData, 
                                                  message, 
                                                  ssdhUser1_pk, 
                                                  new IssuerAndSerialNumber(ssdhUser1));
    System.out.print("\nContent: ");
    System.out.println(new String(received_message));
    
    // ssdhUser2
    System.out.println("\nVerify MAC for ssdhUser2:");
    received_message = getAuthenticatedDataStream(encodedAuthenticatedData,
                                                  message,
                                                  ssdhUser2_pk, 
                                                  new RecipientKeyIdentifier(ssdhUser2));
    
    // kekUser
    System.out.println("\nVerify MAC for kekUser:");
    received_message = getAuthenticatedDataStream(encodedAuthenticatedData,
                                                  message,
                                                  kek,
                                                  new KEKIdentifier(kekID));
    
    System.out.print("\nDecrypted content: ");
    System.out.println(new String(received_message));
    
    System.out.print("\nContent: ");
    System.out.println(new String(received_message));
  }
  
  /**
   * Parses an AuthenticatedData, decrypts the encrypted mac keys for all test recipients
   * using their recipient certificate (or KEK id) for identifying the recipient
   * and verifies the content mac.
   *
   * @param encodedAuthenticatedData the encoded AuthenticatedData object 
   *
   * @exception Exception if some error occurs during mac key decryption / mac verification
   */ 
  public void parseAuthenticatedDataWithRecipientCertOrKEKId(byte[] encodedAuthenticatedData,
                                                             byte[] message) 
    throws Exception {
    
    byte[] received_message;
    // rsaUser1
    System.out.println("\nVerify MAC for rsaUser1:");
    received_message = getAuthenticatedDataStream(encodedAuthenticatedData, 
                                                  message, 
                                                  rsaUser1_pk, 
                                                  rsaUser1,
                                                  null);
    System.out.print("\nContent: ");
    System.out.println(new String(received_message));
    // rsaUser2
    System.out.println("\nVerify MAC for rsaUser2:");
    received_message = getAuthenticatedDataStream(encodedAuthenticatedData,
                                                  message,
                                                  rsaUser2_pk, 
                                                  rsaUser2,
                                                  null);
    
    
    // ssdhUser1
    System.out.println("\nVerify MAC for ssdhUser1:");
    received_message = getAuthenticatedDataStream(encodedAuthenticatedData, 
                                                  message, 
                                                  ssdhUser1_pk, 
                                                  ssdhUser1,
                                                  null);
    System.out.print("\nContent: ");
    System.out.println(new String(received_message));
    // ssdhUser2
    System.out.println("\nVerify MAC for ssdhUser2:");
    received_message = getAuthenticatedDataStream(encodedAuthenticatedData,
                                                  message,
                                                  ssdhUser2_pk, 
                                                  ssdhUser2,
                                                  null);
    //  kekUser
    System.out.println("\nVerify MAC for kekUser:");
    received_message = getAuthenticatedDataStream(encodedAuthenticatedData,
                                                  message,
                                                  kek, 
                                                  null,
                                                  kekID);
    System.out.print("\nDecrypted content: ");
    System.out.println(new String(received_message));
    
    System.out.print("\nContent: ");
    System.out.println(new String(received_message));
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

      // implict mode; with authenticated attributes
      System.out.println("\nCMS AuthenticatedDataOutputStream demo with authenticated attributes [create, implicit mode]:\n");
      encodedAuthenticatedData = createAuthenticatedDataStream(message,
                                                               macAlgorithm,
                                                               macKeyLength,
                                                               digestAlgorithm,
                                                               AuthenticatedDataOutputStream.IMPLICIT);
      // transmit data
      System.out.println("\nCMS AuthenticatedDataOutputStream demo [parse, implicit mode]:\n");
      System.out.println("Decrypt and verify for the several recipients using their index into the recipientInfos field.");
      parseAuthenticatedDataWithRecipientInfoIndex(encodedAuthenticatedData, null);
      System.out.println("Decrypt and verify for the several recipients using their RecipientIdentifier.");
      parseAuthenticatedDataWithRecipientIdentifier(encodedAuthenticatedData, null);
      System.out.println("Decrypt and verify for the several recipients using their certificate or kek.");
      parseAuthenticatedDataWithRecipientCertOrKEKId(encodedAuthenticatedData, null);
      
      // implict mode; without authenticated attributes
      System.out.println("\nCMS AuthenticatedDataOutputStream demo without authenticated attributes [create, implicit mode]:\n");
      encodedAuthenticatedData = createAuthenticatedDataStream(message,
                                                               macAlgorithm,
                                                               macKeyLength,
                                                               null,
                                                               AuthenticatedDataOutputStream.IMPLICIT);
      // transmit data
      System.out.println("\nCMS AuthenticatedDataOutputStream demo [parse, implicit mode]:\n");
      System.out.println("Decrypt and verify for the several recipients using their index into the recipientInfos field.");
      parseAuthenticatedDataWithRecipientInfoIndex(encodedAuthenticatedData, null);
      System.out.println("Decrypt and verify for the several recipients using their RecipientIdentifier.");
      parseAuthenticatedDataWithRecipientIdentifier(encodedAuthenticatedData, null);
      System.out.println("Decrypt and verify for the several recipients using their certificate or kek.");
      parseAuthenticatedDataWithRecipientCertOrKEKId(encodedAuthenticatedData, null);
      
  
      // explict mode; with authenticated attributes
      System.out.println("\nCMS AuthenticatedDataOutputStream demo with authenticated attributes [create, explicit mode]:\n");
      encodedAuthenticatedData = createAuthenticatedDataStream(message,
                                                               macAlgorithm,
                                                               macKeyLength,
                                                               digestAlgorithm,
                                                               AuthenticatedDataOutputStream.EXPLICIT);
      // transmit data
      System.out.println("\nCMS AuthenticatedDataOutputStream demo [parse, explicit mode]:\n");
      System.out.println("Decrypt and verify for the several recipients using their index into the recipientInfos field.");
      parseAuthenticatedDataWithRecipientInfoIndex(encodedAuthenticatedData, message);
      System.out.println("Decrypt and verify for the several recipients using their RecipientIdentifier.");
      parseAuthenticatedDataWithRecipientIdentifier(encodedAuthenticatedData, message);
      System.out.println("Decrypt and verify for the several recipients using their certificate or kek.");
      parseAuthenticatedDataWithRecipientCertOrKEKId(encodedAuthenticatedData, message);
      
      // explict mode; without authenticated attributes
      System.out.println("\nCMS AuthenticatedDataOutputStream demo without authenticated attributes [create, explicit mode]:\n");
      encodedAuthenticatedData = createAuthenticatedDataStream(message,
                                                               macAlgorithm,
                                                               macKeyLength,
                                                               null,
                                                               AuthenticatedDataOutputStream.EXPLICIT);
      // transmit data
      System.out.println("\nCMS AuthenticatedDataOutputStream demo [parse, explicit mode]:\n");
      System.out.println("Decrypt and verify for the several recipients using their index into the recipientInfos field.");
      parseAuthenticatedDataWithRecipientInfoIndex(encodedAuthenticatedData, message);
      System.out.println("Decrypt and verify for the several recipients using their RecipientIdentifier.");
      parseAuthenticatedDataWithRecipientIdentifier(encodedAuthenticatedData, message);
      System.out.println("Decrypt and verify for the several recipients using their certificate or kek.");
      parseAuthenticatedDataWithRecipientCertOrKEKId(encodedAuthenticatedData, message);
      
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

    (new AuthenticatedDataOutputStreamDemo()).start();
    System.out.println("Ready!");
    System.in.read();
  }
}
