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
// $Header: /IAIK-CMS/current/src/demo/cms/envelopedData/EnvelopedDataOutputStreamDemo.java 17    23.08.13 14:22 Dbratko $
// $Revision: 17 $
//


package demo.cms.envelopedData;

import iaik.asn1.CodingException;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.cms.CMSException;
import iaik.cms.ContentInfoOutputStream;
import iaik.cms.EncryptedContentInfoStream;
import iaik.cms.EnvelopedDataOutputStream;
import iaik.cms.EnvelopedDataStream;
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
 * Demonstrates the usage of class {@link iaik.cms.EnvelopedDataOutputStream} and
 * for encrypting data using the CMS type EnvelopedData.
 * 
 * @author Dieter Bratko
 */
public class EnvelopedDataOutputStreamDemo {

   
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
  public EnvelopedDataOutputStreamDemo() throws IOException {
    
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                    EnvelopedDataOutputStream demo                              *");
    System.out.println("*    (shows the usage of the CMS EnvelopedDataOutputStream implementation)       *");
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
   * Creates a CMS <code>EnvelopedData</code> and wraps it into a ContentInfo.
   *
   * @param message the message to be enveloped, as byte representation
   * @return the encoded EnvelopedData object just created, wrapped into a ContentInfo
   *
   * @exception CMSException if the <code>EnvelopedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createEnvelopedDataStream(byte[] message) throws CMSException, IOException {
    
    
    //  a stream from which to read the data to be encrypted
    ByteArrayInputStream is = new ByteArrayInputStream(message);
    
    // the stream to which to write the EnvelopedData
    ByteArrayOutputStream resultStream = new ByteArrayOutputStream();
    EnvelopedDataOutputStream envelopedData;

    //  wrap EnvelopedData into a ContentInfo 
    ContentInfoOutputStream contentInfoStream = 
      new ContentInfoOutputStream(ObjectID.cms_envelopedData, resultStream);
    // create a new EnvelopedData object encrypted with AES
    try {
      envelopedData = new EnvelopedDataOutputStream(contentInfoStream, 
                                                    (AlgorithmID)AlgorithmID.aes128_CBC.clone());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("No implementation for AES.");
    }

    // create the recipient infos
    RecipientInfo[] recipients = new RecipientInfo[2];
    // user1 is the first receiver
    recipients[0] = new KeyTransRecipientInfo(user1_crypt, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // user2 is the second receiver
    recipients[1] = new KeyTransRecipientInfo(user2_crypt, (AlgorithmID)AlgorithmID.rsaEncryption.clone());

    // specify the recipients of the encrypted message
    envelopedData.setRecipientInfos(recipients);
    
    Attribute[] attributes = new Attribute[1];
    
    try {
      // just for testing: set some unprotected attribute
      // content type is data
      CMSContentType contentType = new CMSContentType(ObjectID.cms_data);
      attributes[0] = new Attribute(contentType);
      envelopedData.setUnprotectedAttributes(attributes);
    } catch (Exception ex) {
      throw new CMSException("Error creating attribute: " + ex.toString());   
    }  

    int blockSize = 16; // in real world we would use a block size like 2048
    //  write in the data to be encrypted
    byte[] buffer = new byte[blockSize];
    int bytesRead;
    while ((bytesRead = is.read(buffer)) != -1) {
      envelopedData.write(buffer, 0, bytesRead);
    }
    
    // closing the stream finishes encryption and closes the underlying stream
    envelopedData.close();
    return resultStream.toByteArray();
  }

  /**
   * Decrypts the encrypted content of the given EnvelopedData object for the
   * specified recipient and returns the decrypted (= original) message.
   *
   * @param encoding the encoded EnvelopedData object, wrapped in a ContentInfo
   * @param privateKey the private key to decrypt the message
   * @param recipientInfoIndex the index into the <code>RecipientInfo</code> array
   *                           to which the specified private key belongs
   *
   * @return the recovered message, as byte array
   * @exception CMSException if the message cannot be recovered
   * @exception IOException if an I/O error occurs
   */
  public byte[] getEnvelopedDataStream(byte[] encoding, PrivateKey privateKey, int recipientInfoIndex) throws CMSException, IOException {

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
      
      // get any unprotected attributes:
      Attribute[] attributes = enveloped_data.getUnprotectedAttributes();
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
   * Starts the demo.
   */
  public void start() {
     // the test message
    String m = "This is the test message.";
    System.out.println("Test message: \""+m+"\"");
    System.out.println();
    byte[] message = m.getBytes();

    try {
      byte[] encoding;
      byte[] received_message = null;
      System.out.println("EnvelopedDataOutputStream implementation demo");
      System.out.println("=============================================");


      //
      // test CMS EnvelopedDataStream
      //
      System.out.println("\nEnvelopedData demo [create]:\n");
      encoding = createEnvelopedDataStream(message);
      // transmit data
      System.out.println("\nEnvelopedData demo [parse]:\n");
      // user1 means index 0 (hardcoded for this demo)
      received_message = getEnvelopedDataStream(encoding, user1_crypt_pk, 0);
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

    (new EnvelopedDataOutputStreamDemo()).start();

    DemoUtil.waitKey();
  }
}
