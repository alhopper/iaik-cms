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
// $Header: /IAIK-CMS/current/src/demo/cms/envelopedData/ArcFourEnvelopedDataDemo.java 17    23.08.13 14:22 Dbratko $
// $Revision: 17 $
//

package demo.cms.envelopedData;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.cms.CMSException;
import iaik.cms.EncryptedContentInfoStream;
import iaik.cms.EnvelopedDataStream;
import iaik.cms.KeyTransRecipientInfo;
import iaik.cms.RecipientInfo;
import iaik.security.random.SecRandom;
import iaik.utils.Util;
import iaik.x509.X509Certificate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import demo.keystore.CMSKeyStore;

/**
 * This class demonstrates the EnvelopedDataStream/EncryptedContentInfoStream usages
 * for the ARCFOUR algorithm. The ARCFOUR stream cipher is believed to be compatible with 
 * RC4[TM], a proprietary cipher of RSA Security Inc.. 
 * <p>
 * This demo compares the usage of class EnvelopedDataStream for encrypting the content
 * using ARCFOUR with automatical (transparent) key/parameter handling against explicit
 * key/parameter/EncrypedContentInfoStream handling.
 * <p>
 * All keys and certificates are read from a keystore created by the
 * SetupCMSKeyStore program.
 * <p>
 * ARCFOUR requires no parameters.
 * 
 * @author Dieter Bratko
 */
public class ArcFourEnvelopedDataDemo {

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
  public ArcFourEnvelopedDataDemo() throws IOException {
    
    System.out.println();
    System.out.println("********************************************************************************************");
    System.out.println("*                             ArcFourEnvelopedDataDemo                                     *");
    System.out.println("* (shows the usage of the CMS EnvelopedData type implementation for the ARCFOUR algorithm) *");
    System.out.println("********************************************************************************************");
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
   *
   * @param message the message to be enveloped, as byte representation
   * @param contentEA the content encryption algorithm
   * @param keyLength the key length for the symmetric key
   * @return the DER encoding of the <code>EnvelopedData</code> object just created
   * @exception CMSException if the <code>EnvelopedData</code> object cannot
   *                          be created
   */
  public byte[] createEnvelopedDataStream(byte[] message, AlgorithmID contentEA, int keyLength) throws Exception {

    EnvelopedDataStream enveloped_data;

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);
    // create a new EnvelopedData object 
    try {
      enveloped_data = new EnvelopedDataStream(is, contentEA, keyLength);
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("No implementation for contentEA.getAlgorithm().getName().");
    }


    // create the recipient infos
    RecipientInfo[] recipients = new RecipientInfo[2];
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
   * Creates a CMS <code>EnvelopedDataStream</code> message.
   * <p>
   * Keys and parameters, and EncryptedContentInfoStream are created outside
   * the EnvelopedDataStream class.
   *
   * @param message the message to be enveloped, as byte representation
   * @param cea the content encryption algorithm
   * @param keyLength the key length for the symmetric key
   * @return the DER encoding of the <code>EnvelopedData</code> object just created
   * @exception Exception if the <code>EnvelopedData</code> object cannot
   *                          be created
   */
  public byte[] createEncryptedContentInfoStream(byte[] message, AlgorithmID cea, int keyLength) throws Exception {
       
      AlgorithmID contentEA = (AlgorithmID)cea.clone(); 
      ByteArrayInputStream is = new ByteArrayInputStream(message);
      
      // generate the content encryption key
      KeyGenerator key_gen = KeyGenerator.getInstance("ARCFOUR");
      key_gen.init(keyLength);
      // generate a new key
      SecretKey secretKey = key_gen.generateKey();

      // create the EncryptedContentInfo for the content to be encrypted
      EncryptedContentInfoStream eci = new EncryptedContentInfoStream(ObjectID.cms_data, is);
      // setup the cipher for encryption
      eci.setupCipher(contentEA, secretKey, (AlgorithmParameterSpec)null);

       // create the recipient infos
      RecipientInfo[] recipients = new RecipientInfo[2];
      // user1 is the first receiver
      recipients[0] = new KeyTransRecipientInfo(user1, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
      // encrypt the secret key for recipient 1
      recipients[0].encryptKey(secretKey);
      // user2 is the second receiver
      recipients[1] = new KeyTransRecipientInfo(user2, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
      // encrypt the secret key for recipient 2
      recipients[1].encryptKey(secretKey);
      // now create the EnvelopedDataStream
      EnvelopedDataStream enveloped_data = new EnvelopedDataStream(recipients, eci);

      // return the EnvelopedDate as DER encoded byte array with block size 2048
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      enveloped_data.writeTo(os, 2048);
      byte[] enc = os.toByteArray();
      return enc;

  }

  /**
   * Decrypts the encrypted content of the given <code>EnvelopedData</code> object for the
   * specified recipient and returns the decrypted (= original) message.
   * <p>
   * Decryption and cipher setup and EncryptedContentInfoStrean processing 
   * is performed outside class EnvelopedDataStream.
   *
   * @param encoding the <code>EnvelopedData</code> object as DER encoded byte array
   * @param privateKey the private key to decrypt the message
   * @param recipientInfoIndex the index into the <code>RecipientInfo</code> array
   *                           to which the specified private key belongs
   *
   * @return the recovered message, as byte array
   * @exception Exception if the message cannot be recovered
   */
  public byte[] getEncryptedContentInfoStream(byte[] encoding, PrivateKey privateKey, int recipientInfoIndex) throws Exception {

    // create the EnvelopedData object from a DER encoded byte array
    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    EnvelopedDataStream enveloped_data = new EnvelopedDataStream(is);

    AlgorithmParameterSpec params = null;
    // get the recipient infos
    RecipientInfo[]  recipients = enveloped_data.getRecipientInfos();

    System.out.println("\nThis message can be decrypted by the owners of the following certificates:");

    for (int i=0; i<recipients.length; i++) {
      System.out.println("Recipient "+(i+1)+":");
      System.out.println(recipients[i].getRecipientIdentifiers()[0]);
    }
    // decrypt symmetric content encryption key, e.g.:
    SecretKey secretKey = recipients[recipientInfoIndex].decryptKey(user1_pk);

    //get the ECI from the enveloped data:
    EncryptedContentInfoStream eci = (EncryptedContentInfoStream)enveloped_data.getEncryptedContentInfo();
    System.out.println("\nContent type of encrypted data: " + eci.getContentType());
    //get the content encryption algorithm:
    AlgorithmID contentEA = eci.getContentEncryptionAlgorithm();
    System.out.println("Content Encryption Algorithm: " + contentEA);
    //now setup the cipher with previously decrypted recipient key amd params
    eci.setupCipher(secretKey);
    //get and read the data thereby actually performing the decryption
    InputStream data_is = eci.getInputStream();
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    Util.copyStream(data_is, baos, null);
    byte[] decrypted = baos.toByteArray();
    return decrypted;
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
   * @exception Exception if the message cannot be recovered
   */
  public byte[] getEnvelopedDataStream(byte[] encoding, PrivateKey privateKey, int recipientInfoIndex) throws Exception {

    // create the EnvelopedData object from a DER encoded byte array
    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    EnvelopedDataStream enveloped_data = new EnvelopedDataStream(is);

    // get the recipient infos
    RecipientInfo[]  recipients = enveloped_data.getRecipientInfos();

    System.out.println("\nThis message can be decrypted by the owners of the following certificates:");

    for (int i=0; i<recipients.length; i++) {
      System.out.println("Recipient "+(i+1)+": ");
      System.out.println(recipients[i].getRecipientIdentifiers()[0]);
    }
    
    EncryptedContentInfoStream eci = enveloped_data.getEncryptedContentInfo();
    System.out.println("\nContent type of encrypted data: " + eci.getContentType());
    //get the content encryption algorithm:
    AlgorithmID contentEA = eci.getContentEncryptionAlgorithm();
    System.out.println("Content Encryption Algorithm: " + contentEA);
    //now setup the cipher with previously decrypted recipient key amd params
    enveloped_data.setupCipher(privateKey, recipientInfoIndex);
    //get and read the data thereby actually performing the decryption
    InputStream data_is = enveloped_data.getInputStream();
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    Util.copyStream(data_is, baos, null);
    byte[] decrypted = baos.toByteArray();
    return decrypted;

  }

  
  
  /**
   * Starts the test.
   */
  public void start() {
     // the test message
    String m = "This is the test message.";
    System.out.println("Test message: "+m);
    System.out.println();
    byte[] message = m.getBytes();

    try {
      byte[] data;
      byte[] received_message = null;


      // the stream implementation
      //
      // test CMS EnvelopedDataStream
      //

      System.out.println("\nEnvelopedDataStream demo for algorithm ARCFOUR [create]:\n");
      data = createEnvelopedDataStream(message, (AlgorithmID)AlgorithmID.arcfour.clone(), 128);

      // transmit data
      System.out.println("\nEnvelopedDataStream demo [parse]:\n");
      // user1 means index 0 (hardcoded for this demo)
      received_message = getEnvelopedDataStream(data, user1_pk, 0);
      //received_message = getEnvelopedDataStream(data, user2_pk, 1);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(received_message));

      // test against EncryptedContentInfoStream - EnvelopedDataStream creation

      System.out.println("\nEnvelopedDataStream demo for algorithm ARCFOUR [create]:\n");
      
      System.out.println("Create EncryptedContentInfo for EnvelopedData...");
      data = createEncryptedContentInfoStream(message, (AlgorithmID)AlgorithmID.arcfour.clone(), 128);
      // transmit data
      System.out.println("\nEnvelopedDataStream demo [parse]:\n");
      // user1 means index 0 (hardcoded for this demo)
      received_message = getEnvelopedDataStream(data, user1_pk, 0);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(received_message));
      
      System.out.println("\nEnvelopedDataStream demo for algorithm ARCFOUR [create]:\n");
      data = createEnvelopedDataStream(message, (AlgorithmID)AlgorithmID.arcfour.clone(), 128);
      // transmit data
   
      System.out.println("\nEnvelopedDataStream demo [parse]:\n");
      // user1 means index 0 (hardcoded for this demo)
      System.out.println("Decrypt EncryptedContentInfo of EnvelopedData...");
      received_message = getEncryptedContentInfoStream(data, user1_pk, 0);
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
   * @exception Exception
   *            if some error occurs
   */
  public static void main(String argv[]) throws Exception {

   	demo.DemoUtil.initDemos();

    (new ArcFourEnvelopedDataDemo()).start();
    System.out.println("\nReady!");
    System.in.read();
  }
}
