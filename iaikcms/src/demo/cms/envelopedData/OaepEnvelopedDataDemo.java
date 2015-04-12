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

package demo.cms.envelopedData;

import iaik.asn1.OCTET_STRING;
import iaik.asn1.structures.AlgorithmID;
import iaik.cms.CMSException;
import iaik.cms.ContentInfo;
import iaik.cms.ContentInfoStream;
import iaik.cms.EncryptedContentInfo;
import iaik.cms.EncryptedContentInfoStream;
import iaik.cms.EnvelopedData;
import iaik.cms.EnvelopedDataStream;
import iaik.cms.KeyTransRecipientInfo;
import iaik.cms.RecipientInfo;
import iaik.cms.SecurityProvider;
import iaik.pkcs.pkcs1.MGF1ParameterSpec;
import iaik.pkcs.pkcs1.MaskGenerationAlgorithm;
import iaik.pkcs.pkcs1.RSAOaepParameterSpec;
import iaik.utils.Util;
import iaik.x509.X509Certificate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidParameterSpecException;

import demo.DemoUtil;
import demo.keystore.CMSKeyStore;


/**
 * This class demonstrates the CMS EnvelopedData implementation for
 * the RSA-OAEP (PKCS#1v2.1) algorithm.
 * <p>
 * All keys and certificates are read from a keystore created by the
 * SetupKeyStore program.
 * @version File Revision <!-- $$Revision: --> 14 <!-- $ -->
 * 
 * @author Dieter Bratko
 */
public class OaepEnvelopedDataDemo {

  // certificate of user 1
  X509Certificate user1;
  // private key of user 1
  PrivateKey user1_pk;
  // certificate of user 2
  X509Certificate user2;
  // private key of user 2
  PrivateKey user2_pk;

  /**
   * Setup the demo certificate chains.
   *
   * Keys and certificate are retrieved from the demo KeyStore.
   *
   * @exception IOException if an file read error occurs
   */
  public OaepEnvelopedDataDemo() throws IOException {
    
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                           OaepEnvelopedDataDemo                                *");
    System.out.println("*    (shows the usage of the CMS EnvelopedData type with the RSA OAEP method)    *");
    System.out.println("**********************************************************************************");
    System.out.println();
    
    // add all certificates to the list
    X509Certificate[] certs = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT);
    user1 = certs[0];
    user1_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT);
    user2 = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_)[0];
    user2_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_);
  }


  /**
   * Creates a CMS <code>EnvelopedDataStream</code> message.
   *
   * @param message the message to be enveloped, as byte representation
   * @return the BER encoded ContentInfo containing the EnvelopedData object just created
   *
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
    RecipientInfo[] recipients = new RecipientInfo[2];
    // user1 is the first receiver (OAEP with default parameters)
    recipients[0] = new KeyTransRecipientInfo(user1, (AlgorithmID)AlgorithmID.rsaesOAEP.clone());
    // user2 is the second receiver (OAEP with user defined parameters)
    AlgorithmID hashID = (AlgorithmID)AlgorithmID.sha256.clone();
    AlgorithmID mgfID = (AlgorithmID)AlgorithmID.mgf1.clone();
    AlgorithmID pSourceID = (AlgorithmID)AlgorithmID.pSpecified.clone();
    // empty label
    byte[] label = {};
    AlgorithmID oaepID = createOaepAlgorithmID(hashID, mgfID, pSourceID, label);
    recipients[1] = new KeyTransRecipientInfo(user2, oaepID);
    // specify the recipients of the encrypted message
    enveloped_data.setRecipientInfos(recipients);
    // return the EnvelopedDate as DER encoded byte array with block size 2048
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    enveloped_data.setBlockSize(2048);
    ContentInfoStream cis = new ContentInfoStream(enveloped_data);
    cis.writeTo(os);
    return os.toByteArray();
  }

  /**
   * Decrypts the encrypted content of the given EnvelopedData object for the
   * specified recipient and returns the decrypted (= original) message.
   *
   * @param encoding the BER encoded ContentInfo containing an EnvelopedData object
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
      System.out.println("Recipient: "+(i+1));
      System.out.print(recipients[i].getRecipientIdentifiers()[0]);
    }

    // decrypt the message
    try {
      enveloped_data.setupCipher(privateKey, recipientInfoIndex);
      InputStream decrypted = enveloped_data.getInputStream();
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      Util.copyStream(decrypted, os, null);

      return os.toByteArray();

    } catch (InvalidKeyException ex) {
      System.out.println("Private key error: "+ex.getMessage());
      return null;
    } catch (NoSuchAlgorithmException ex) {
      System.out.println("Content encryption algorithm not implemented: "+ex.getMessage());
      return null;
    }
  }


  /**
   * Creates a CMS <code>EnvelopedData</code> message.
   *
   * @param message the message to be enveloped, as byte representation
   * @return a BER encoded ContentInfo holding the EnvelopedData object just created
   * @exception CMSException if the <code>EnvelopedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createEnvelopedData(byte[] message) throws CMSException, IOException {

    EnvelopedData enveloped_data;

    // create a new EnvelopedData object encrypted with TripleDES CBC
    try {
      enveloped_data = new EnvelopedData(message, (AlgorithmID)AlgorithmID.des_EDE3_CBC.clone());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("No implementation for Triple-DES-CBC.");
    }

 
    // create the recipient infos
    RecipientInfo[] recipients = new RecipientInfo[2];
    // user1 is the first receiver (OAEP with default parameters)
    recipients[0] = new KeyTransRecipientInfo(user1, (AlgorithmID)AlgorithmID.rsaesOAEP.clone());
    // user2 is the second receiver (OAEP with user defined parameters)
    AlgorithmID hashID = (AlgorithmID)AlgorithmID.sha256.clone();
    AlgorithmID mgfID = (AlgorithmID)AlgorithmID.mgf1.clone();
    AlgorithmID pSourceID = (AlgorithmID)AlgorithmID.pSpecified.clone();
    // empty label
    byte[] label = {};
    AlgorithmID oaepID = createOaepAlgorithmID(hashID, mgfID, pSourceID, label);
    recipients[1] = new KeyTransRecipientInfo(user2, oaepID);
    // specify the recipients of the encrypted message
    enveloped_data.setRecipientInfos(recipients);
    ContentInfo ci = new ContentInfo(enveloped_data);
    // return the EnvelopedData as DER encoded byte array
    return ci.toByteArray();
  }

  /**
   * Decrypts the encrypted content of the given <code>EnvelopedData</code> object for the
   * specified recipient and returns the decrypted (= original) message.
   *
   * @param encoding the ContentInfo encoding holding an EnvelopedData
   * @param privateKey the private key to decrypt the message
   * @param recipientInfoIndex the index into the <code>RecipientInfo</code> array
   *                           to which the specified private key belongs
   *
   * @return the recovered message, as byte array
   * @exception CMSException if the message cannot be recovered
   * @exception IOException if an I/O error occurs
   */
  public byte[] getEnvelopedData(byte[] encoding, PrivateKey privateKey, int recipientInfoIndex) 
    throws CMSException, IOException {
    
    EnvelopedData enveloped_data = new EnvelopedData(new ByteArrayInputStream(encoding));

    System.out.println("Information about the encrypted data:");
    EncryptedContentInfo eci = (EncryptedContentInfo)enveloped_data.getEncryptedContentInfo();
    System.out.println("Content type: "+eci.getContentType().getName());
    System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());

    System.out.println("\nThis message can be decrypted by the owners of the following certificates:");
    RecipientInfo[] recipients = enveloped_data.getRecipientInfos();
    for (int i=0; i<recipients.length; i++) {
      System.out.println("Recipient: "+(i+1));
      System.out.print(recipients[i].getRecipientIdentifiers()[0]);
    }

    // decrypt the message
    try {
      enveloped_data.setupCipher(privateKey, recipientInfoIndex);
      return enveloped_data.getContent();

    } catch (InvalidKeyException ex) {
      System.out.println("Private key error: "+ex.getMessage());
      return null;
    } catch (NoSuchAlgorithmException ex) {
      System.out.println("Content encryption algorithm not implemented: "+ex.getMessage());
      return null;
    }
  }

  /**
   * Creates a RSA-OAEP AlgorithmID with the supplied parameters (hash algorithm id,
   * mask generation function, PSource algorithm and label).
   *
   * @param hashID the hash algorithm to be used
   * @param mgfID the mask generation function to be used
   * @param pSourceID the PSource algorithm
   * @param label the value of the PSource label parameter
   *
   * @return the RSA-OAEP algorithm id with the given parameters 
   *
   * @exception CMSException if the parameters cannot be created/set
   *            or there is no AlgorithmParameters implementation for RSA-OAEP
   */
  public AlgorithmID createOaepAlgorithmID(AlgorithmID hashID, 
                                           AlgorithmID mgfID, 
                                           AlgorithmID pSourceID,
                                           byte[] label)
    throws CMSException {
        
    AlgorithmID rsaOaepID = (AlgorithmID)AlgorithmID.rsaesOAEP.clone();
    mgfID.setParameter(hashID.toASN1Object());
    pSourceID.setParameter(new OCTET_STRING(label));
    // hash and mgf engines
    MessageDigest hashEngine = null;
    MaskGenerationAlgorithm mgfEngine = null;
    try {
      hashEngine = hashID.getMessageDigestInstance();
      mgfEngine = mgfID.getMaskGenerationAlgorithmInstance();
      MGF1ParameterSpec mgf1ParamSpec = new MGF1ParameterSpec(hashID);
      mgf1ParamSpec.setHashEngine(hashEngine);
      mgfEngine.setParameters(mgf1ParamSpec);
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException(ex.toString());     
    } catch (InvalidAlgorithmParameterException ex) {
      throw new CMSException("Cannot init MGF engine: " + ex.toString());   
    }
      // create the RSAOaepParameterSpec
    RSAOaepParameterSpec oaepParamSpec = new RSAOaepParameterSpec(hashID, mgfID, pSourceID);
    // set engines
    oaepParamSpec.setHashEngine(hashEngine);
    oaepParamSpec.setMGFEngine(mgfEngine);
    
    AlgorithmParameters oaepParams = null;
    try {
      oaepParams = AlgorithmParameters.getInstance(SecurityProvider.IMPLEMENTATION_NAME_RSA_OAEP, "IAIK");
      oaepParams.init(oaepParamSpec);
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("RSA-OAEP implementation of provider IAIK not available!");    
    } catch (NoSuchProviderException ex) {
      throw new CMSException("RSA-OAEP implementation of provider IAIK not available!");  
    } catch (InvalidParameterSpecException ex) {
      throw new CMSException("Cannot init OAEP params: " + ex.getMessage());  
    }    
   
    rsaOaepID.setAlgorithmParameters(oaepParams);
    return rsaOaepID;
  } 



  /**
   * Shows thw CMS EnvelopedData implementation for
   * the RSA-OAEP (PKCS#1v2.1) algorithm.
   */
  public void start() {
     // the test message
    String m = "This is the test message.";
    System.out.println("Test message: \""+m+"\"");
    System.out.println();
    byte[] message = m.getBytes();

    try {
      byte[] encodedEnvelopedData;
      byte[] received_message = null;
      System.out.println("Stream implementation demos (OAEP)");
      System.out.println("==================================");

     

      // the stream implementation
      //
      // test CMS EnvelopedDataStream
      //
      System.out.println("\nEnvelopedDataStream demo [create]:\n");
      encodedEnvelopedData = createEnvelopedDataStream(message);

      // transmit data
      System.out.println("\nEnvelopedDataStream demo [parse]:\n");
      // user1 means index 0 (hardcoded for this demo)
      System.out.println("\nDecrypt for recipient 1:\n");
      received_message = getEnvelopedDataStream(encodedEnvelopedData, user1_pk, 0);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(received_message));
      
      // user2 means index 1 (hardcoded for this demo)
      System.out.println("\nDecrypt for recipient 1:\n");
      received_message = getEnvelopedDataStream(encodedEnvelopedData, user2_pk, 1);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(received_message));

      
      // the non-stream implementation
      System.out.println("\nNon-stream implementation demos (OAEP)");
      System.out.println("========================================");
     
      //
      // test CMS EnvelopedData
      //
      System.out.println("\nEnvelopedData demo [create]:\n");
      encodedEnvelopedData = createEnvelopedData(message);
      // transmit data
      System.out.println("\nEnvelopedData demo [parse]:\n");
      System.out.println("\nDecrypt for recipient 1:\n");
      // user1 means index 0 (hardcoded for this demo)
      received_message = getEnvelopedData(encodedEnvelopedData, user1_pk, 0);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(received_message));
      
      System.out.println("\nDecrypt for recipient 2:\n");
      // user2 means index 1 (hardcoded for this demo)
      received_message = getEnvelopedData(encodedEnvelopedData, user2_pk, 1);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(received_message));

      System.out.println("Ready!");

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
    (new OaepEnvelopedDataDemo()).start();

    DemoUtil.waitKey();
  }
}
