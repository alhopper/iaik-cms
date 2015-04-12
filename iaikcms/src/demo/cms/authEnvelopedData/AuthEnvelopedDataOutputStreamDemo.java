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
// $Header: /IAIK-CMS/current/src/demo/cms/authEnvelopedData/AuthEnvelopedDataOutputStreamDemo.java 5     23.08.13 14:20 Dbratko $
// $Revision: 5 $
//


package demo.cms.authEnvelopedData;

import iaik.asn1.CodingException;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.cms.CMSException;
import iaik.cms.ContentInfoOutputStream;
import iaik.cms.EncryptedContentInfoStream;
import iaik.cms.AuthEnvelopedDataOutputStream;
import iaik.cms.AuthEnvelopedDataStream;
import iaik.cms.KeyTransRecipientInfo;
import iaik.cms.RecipientInfo;
import iaik.cms.attributes.CMSContentType;
import iaik.security.random.SecRandom;
import iaik.utils.CryptoUtils;
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
 * Demonstrates the usage of class {@link iaik.cms.AuthEnvelopedDataOutputStream} and
 * for authenticated encrypting data using the CMS type AuthEnvelopedData
 * according to <a href = "http://www.ietf.org/rfc/rfc5083.txt" target="_blank">RFC 5083</a>.
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
 * 
 * @author Dieter Bratko
 */
public class AuthEnvelopedDataOutputStreamDemo {

   
  // encryption certificate of user 1
  X509Certificate user1_crypt;
  // encryption private key of user 1
  PrivateKey user1_crypt_pk;
  // encryption certificate of user 2
  X509Certificate user2_crypt;
  // encryption private key of user 2
  PrivateKey user2_crypt_pk;
  
  // secure random number generator
  SecureRandom random;

  /**
   * Setup the demo certificate chains.
   *
   * Keys and certificate are retrieved from the demo KeyStore.
   *
   * @exception IOException if an file read error occurs
   */
  public AuthEnvelopedDataOutputStreamDemo() throws IOException {
    
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                    AuthEnvelopedDataOutputStream demo                          *");
    System.out.println("*    (shows the usage of the CMS AuthEnvelopedDataOutputStream implementation)   *");
    System.out.println("**********************************************************************************");
    System.out.println();
    
    // encryption certs
    user1_crypt = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT)[0];
    user1_crypt_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT);
    user2_crypt = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_)[0];
    user2_crypt_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_);

    random = SecRandom.getDefault();

  }


  /**
   * Creates a CMS <code>AuthEnvelopedData</code> and wraps it into a ContentInfo.
   *
   * @param message the message to be enveloped, as byte representation
   * @param contentAuthEncAlg the id of the content-authenticated encryption algorithm
   * 
   * @return the encoded AuthEnvelopedData object just created, wrapped into a ContentInfo
   *
   * @exception CMSException if the <code>AuthEnvelopedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createAuthEnvelopedData(byte[] message, AlgorithmID contentAuthEncAlg)
    throws CMSException, IOException {
    
    System.out.println("Create AuthEnvelopedData message for : " + contentAuthEncAlg.getName());
    
    //  a stream from which to read the data to be encrypted
    ByteArrayInputStream is = new ByteArrayInputStream(message);
    
    // the stream to which to write the AuthEnvelopedData
    ByteArrayOutputStream resultStream = new ByteArrayOutputStream();
    AuthEnvelopedDataOutputStream authEnvelopedData;

    //  wrap AuthEnvelopedData into a ContentInfo 
    ContentInfoOutputStream contentInfoStream = 
      new ContentInfoOutputStream(ObjectID.cms_authEnvelopedData, resultStream);
   
    // create a new AuthEnvelopedData object 
    authEnvelopedData = new AuthEnvelopedDataOutputStream(contentInfoStream, 
                                                          contentAuthEncAlg);
    
    
    if (contentAuthEncAlg.equals(AlgorithmID.aes128_CCM) || 
        contentAuthEncAlg.equals(AlgorithmID.aes192_CCM) ||
        contentAuthEncAlg.equals(AlgorithmID.aes256_CCM)) {
      // for aes-ccm we need to know the data input length in advance
      authEnvelopedData.setInputLength(message.length);
    }
  
    // create the recipient infos
    RecipientInfo[] recipients = new RecipientInfo[2];
    // user1 is the first receiver
    recipients[0] = new KeyTransRecipientInfo(user1_crypt, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // user2 is the second receiver
    recipients[1] = new KeyTransRecipientInfo(user2_crypt, (AlgorithmID)AlgorithmID.rsaEncryption.clone());

    // specify the recipients of the encrypted message
    authEnvelopedData.setRecipientInfos(recipients);
    
    try {
      // just for demonstration: set some authenticated attribute
      // content type is data
      CMSContentType contentType = new CMSContentType(ObjectID.cms_data);
      Attribute[] attributes = { new Attribute(contentType) };
      authEnvelopedData.setAuthenticatedAttributes(attributes);
    } catch (Exception ex) {
      throw new CMSException("Error creating attribute: " + ex.toString());   
    }  

    int blockSize = 16; // in real world we would use a block size like 2048
    //  write in the data to be encrypted
    byte[] buffer = new byte[blockSize];
    int bytesRead;
    while ((bytesRead = is.read(buffer)) != -1) {
      authEnvelopedData.write(buffer, 0, bytesRead);
    }
    
    // closing the stream finishes encryption and closes the underlying stream
    authEnvelopedData.close();
    return resultStream.toByteArray();
  }

  /**
   * Decrypts the encrypted content of the given AuthEnvelopedData object and
   * verifies the message authentication code for the specified recipient.
   *
   * @param encoding the encoded AuthEnvelopedData object, wrapped in a ContentInfo
   * @param privateKey the private key to decrypt the message
   * @param recipientInfoIndex the index into the <code>RecipientInfo</code> array
   *                           to which the specified private key belongs
   *
   * @return the recovered message, as byte array
   * @exception CMSException if the message cannot be recovered
   * @exception IOException if an I/O error occurs
   */
  public byte[] getAuthEnvelopedDataStream(byte[] encoding, PrivateKey privateKey, int recipientInfoIndex) throws CMSException, IOException {

    // create the AuthEnvelopedData object from a BER encoded byte array
    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    
    AuthEnvelopedDataStream enveloped_data = new AuthEnvelopedDataStream(is);

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
      
      // get any unprotected attributes:
      Attribute[] attributes = enveloped_data.getAuthenticatedAttributes();
      if ((attributes != null) && (attributes.length > 0)) {
        System.out.println("Attributes included: ");
        // we know we have used content type
        CMSContentType contentType = (CMSContentType)attributes[0].getAttributeValue();
        System.out.println(contentType);  
      }  

      return os.toByteArray();

    } catch (InvalidKeyException ex) {
      throw new CMSException("Private key error: "+ex.toString());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.getMessage());
    } catch (CodingException ex) {
      throw new CMSException("Cannot get unprotected attributes: "+ex.toString());
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
      byte[] encoding;
      byte[] received_message = null;
      System.out.println("AuthEnvelopedDataOutputStream implementation demo");
      System.out.println("==================================================");


      //
      // test CMS AuthEnvelopedDataOutputStream
      //
      System.out.println("\nAuthEnvelopedData demo [create]:\n");
      encoding = createAuthEnvelopedData(message, (AlgorithmID)contentAuthEncAlg.clone());
      // transmit data
      System.out.println("\nAuthEnvelopedData demo [parse]:\n");
      // user1 means index 0 (hardcoded for this demo)
      received_message = getAuthEnvelopedDataStream(encoding, user1_crypt_pk, 0);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(received_message));
      
      if (CryptoUtils.equalsBlock(received_message, message) == false) {
        throw new Exception("Decrypted content not equal to original one!");
      }
 
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
   *            if an some error occurs 
   */
  public static void main(String argv[]) throws Exception {

    demo.DemoUtil.initDemos();

    (new AuthEnvelopedDataOutputStreamDemo()).start();

    DemoUtil.waitKey();
  }
}
