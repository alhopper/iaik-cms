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
// $Header: /IAIK-CMS/current/src/demo/smime/basic/CMSStreamDemo.java 27    28.11.13 16:06 Dbratko $
// $Revision: 27 $
//

package demo.smime.basic;

import iaik.asn1.structures.AlgorithmID;
import iaik.cms.IssuerAndSerialNumber;
import iaik.smime.SMimeEncrypted;
import iaik.smime.SMimeSigned;
import iaik.utils.CryptoUtils;
import iaik.utils.Util;
import iaik.x509.X509Certificate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.security.PrivateKey;
import java.util.Random;

import demo.DemoSMimeUtil;
import demo.DemoUtil;
import demo.keystore.CMSKeyStore;

/**
 * This class shows the usage of the SMimeSigned and SMimeEncrypted classes. 
 * These classes can be used to create/parse signed and/or encrypted CMS messages.
 * This demo does not use the JavaMail API.
 *
 * @see iaik.smime.SMimeSigned
 * @see iaik.smime.SMimeEncrypted
 * 
 * @author Dieter Bratko
 */
public class CMSStreamDemo {

  // the signer private key
  PrivateKey[] signerPrivateKeys;
  // the signer certificate
  X509Certificate rsaSignerCertificate;
  // the signer certificate
  X509Certificate dsaSignerCertificate;
  // the recipient private key
  PrivateKey[] recipientPrivateKeys;
  // the recipient certificate
  X509Certificate[] recipientCertificates;
  // the certificate chain
  X509Certificate[] signerCertificates;
  // buffer with test data to sign and/or encrypt
  byte[] buffer;
  // size of the buffer
  final static int BUF_SIZE = 10000;
  
  /**
   * Empty default constructor.
   */
  public CMSStreamDemo() {
    
    System.out.println();
    System.out.println("******************************************************************************************");
    System.out.println("*                                   CMSStreamDemo                                        *");
    System.out.println("*       (shows the usage of the IAIK-CMS SMimeSigned and SMimeEncrypted classes)         *");
    System.out.println("******************************************************************************************");
    System.out.println();
    
    // create some random data for the test
    buffer = new byte[BUF_SIZE];
    Random rnd = new Random();
    rnd.nextBytes(buffer);
  }
  
  /**
   * Reads the required keys and certificates from the demo keystore.
   * 
   * @exception Exception if some error occurs when reading from the keystore
   */
  public void setupCertificates() throws Exception {
    // get the certificates from the KeyStore
    // we use two signers just for demonstration
    signerPrivateKeys = new PrivateKey[2];
    // RSA signer
    X509Certificate[] rsaCerts = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    rsaSignerCertificate = rsaCerts[0];
    signerPrivateKeys[0] = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    // DSA signer
    X509Certificate[] dsaCerts = CMSKeyStore.getCertificateChain(CMSKeyStore.DSA, CMSKeyStore.SZ_1024_SIGN);
    dsaSignerCertificate = dsaCerts[0];
    signerPrivateKeys[1] = CMSKeyStore.getPrivateKey(CMSKeyStore.DSA, CMSKeyStore.SZ_1024_SIGN);
    signerCertificates = new X509Certificate[rsaCerts.length + dsaCerts.length];
    System.arraycopy(rsaCerts, 0, signerCertificates, 0, dsaCerts.length);
    System.arraycopy(dsaCerts, 0, signerCertificates, rsaCerts.length, dsaCerts.length);

    // get the recipients keys and certificates
    recipientPrivateKeys = new PrivateKey[2];
    recipientPrivateKeys[0] = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT);
    recipientPrivateKeys[1] = CMSKeyStore.getPrivateKey(CMSKeyStore.ESDH, CMSKeyStore.SZ_1024_CRYPT);
    recipientCertificates = new X509Certificate[2];
    recipientCertificates[0] = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT)[0];
    recipientCertificates[1] = CMSKeyStore.getCertificateChain(CMSKeyStore.ESDH, CMSKeyStore.SZ_1024_CRYPT)[0];
  }

  /**
   * Uses class {@link iaik.smime.SMimeEncrypted SMimeEncrypted} to encrypt some data, encode it,
   * and finally parses the encoding to decrypt and recover the original content.
   *
   * @param contentEA the content encryption algorithm to be used
   * @param keyWrapAlg the key wrap algorithm to be used for encrypting the temporary content encryption key
   * @param keyLength the length of the content encryption key to be created and used
   * @param recipientIndex the index into the recipientInfos field indicating for which recipient the message
   *                       shall be decrypted
   *
   * @exception if some error occurs
   */
  public void testSMimeEncrypted(AlgorithmID contentEA, AlgorithmID keyWrapAlg, int keyLength, int recipientIndex) throws Exception {

    // repository for the encrypted message
    byte[] encrypted_message;
    // the InputStream containing the data to encrypt
    InputStream is = new ByteArrayInputStream(buffer);
    // the OutputStream where the data shall be written to
    ByteArrayOutputStream os = new ByteArrayOutputStream();

    // encrypt with DES/CBC and default key length
    SMimeEncrypted encrypted = new SMimeEncrypted(is, contentEA, keyLength);
    // add one RSA recipient
    encrypted.addRecipient(recipientCertificates[0], (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // add one ESDH recipient
    encrypted.addRecipient(recipientCertificates[1], (AlgorithmID)AlgorithmID.esdhKeyAgreement.clone(), keyWrapAlg, keyLength);
    
    // encrypt and write the data to the output stream
    encrypted.writeTo(os);
    // finished
    os.close();
    // get the encrypted message from the ByteArrayOutputStream
    encrypted_message = os.toByteArray();
    
    // and now decrypt the data
    is = new ByteArrayInputStream(encrypted_message);
    encrypted = new SMimeEncrypted(is);
    // use this private key to decrypt the symmetric key of recipient 0
    encrypted.decryptSymmetricKey(recipientPrivateKeys[recipientIndex], recipientIndex);
    // get the InputStream with the decrypted data
    InputStream data = encrypted.getInputStream();

    // reset our output stream
    os.reset();
    // write the decrypted data to an output stream
    // copy the data
    Util.copyStream(data, os, null);
    os.close();

    // original and 'received' message must be the same
    if (!CryptoUtils.equalsBlock(buffer, os.toByteArray()))
      throw new RuntimeException("Error: messages are not equal!");
  }

  /**
   * Uses class {@link iaik.smime.SMimeSigned SMimeSigned} to sign some data, encode it,
   * and finally parses the encoding to verify the signature.
   *
   * @param mode either {@link iaik.smime.SMimeSigned#IMPLICIT implicit} or
   *                    {@link iaik.smime.SMimeSigned#EXPLICIT explicit} to indicate
   *                    whether the content shall be included in the signature or
   *                    transmitted out-of-band
   * 
   * @exception if some error occurs
   */
  public void testSMimeSigned(int mode) throws Exception {

    // repository for the signed message
    byte[] signed_message = null;
    // repository for the signature
    byte[] signature;
    // the InputStream containing the data to sign
    InputStream is = new ByteArrayInputStream(buffer);
    // the OutputStream where the data shall be written to
    ByteArrayOutputStream os = new ByteArrayOutputStream();

    // create an implicitly/explicitly signed message
    SMimeSigned signed = new SMimeSigned(is, mode);
    // these certificates are sent within the signature
    signed.setCertificates(signerCertificates);
    // add two signers for testing
    signed.addSigner(signerPrivateKeys[0], 
                     new IssuerAndSerialNumber(rsaSignerCertificate));
    signed.addSigner(signerPrivateKeys[1], 
                     new IssuerAndSerialNumber(dsaSignerCertificate), 
                     (AlgorithmID)AlgorithmID.sha1.clone(),
                     (AlgorithmID)AlgorithmID.dsaWithSHA.clone());
    

    if (mode == SMimeSigned.EXPLICIT) {
      // write the data to the out-of-band file
      ByteArrayOutputStream out_data = new ByteArrayOutputStream();
      Util.copyStream(signed.getInputStream(), out_data, null);
      out_data.close();
      signed_message = out_data.toByteArray();
    }

    // write the signature or the data+signature to the output stream
    signed.writeTo(os);
    os.close();
    signature = os.toByteArray();

    // and now verify the signature
    is = new ByteArrayInputStream(signature);
    signed = new SMimeSigned(is);
    if (mode == SMimeSigned.EXPLICIT) {
      // content data has been not included 
      signed.setInputStream(new ByteArrayInputStream(signed_message));
    }
    
    // get the InputStream with the signed, plain data
    InputStream data = signed.getInputStream();

    // reset our output stream
    os.reset();
    // write the verified data to the output stream
    // copy the data
    Util.copyStream(data, os, null);
    os.close();

    // now verify the signed data and print the certificate of the signer
    // (verify() verifies signer at index 0)
    X509Certificate cert = signed.verify();
    System.out.println("Signature OK from: "+cert.getSubjectDN());
    // verify our second test signer
    cert = signed.verify(1);
    System.out.println("Signature OK from: "+cert.getSubjectDN());

    // original and 'received' message must be the same
    if (!CryptoUtils.equalsBlock(buffer, os.toByteArray()))
      throw new RuntimeException("Error: messages are not equal!");
  }
  
  /**
   * Uses class {@link iaik.smime.SMimeSigned SMimeSigned} and class {@link iaik.smime.SMimeEncrypted SMimeEncrypted}
   * to sign and encrypt some data, encode it, and finally parses the encoding to decrypt and recover the original content
   * and verify the signature.
   *
   * @param contentEA the content encryption algorithm to be used
   * @param keyWrapAlg the key wrap algorithm to be used for encrypting the temporary content encryption key
   * @param keyLength the length of the content encryption key to be created and used
   * @param recipientIndex the index into the recipientInfos field indicating for which recipient the message
   *                       shall be decrypted
   *
   * @exception if some error occurs
   */
  public void testSMimeSignedAndEncrypted(AlgorithmID contentEA, AlgorithmID keyWrapAlg, int keyLength, int recipientIndex) throws Exception {

    // repository for the signed and encrypted message
    byte[] signed_encrpyted_message;
    // the InputStream containing the data to sign and encrypt
    InputStream is = new ByteArrayInputStream(buffer);
    // the OutputStream where the data shall be written to
    ByteArrayOutputStream os = new ByteArrayOutputStream();

    // we have to sign and encrypt => connect 2 streams
    PipedOutputStream piped_out = new PipedOutputStream();
    PipedInputStream piped_in = new PipedInputStream(piped_out);

    // create an implicit signed message (signature contains message)
    SMimeSigned signed = new SMimeSigned(is, SMimeSigned.IMPLICIT);
    // these certificates are sent within the signature
    signed.setCertificates(signerCertificates);
    // add two signers for testing
    signed.addSigner(signerPrivateKeys[0],
                     new IssuerAndSerialNumber(rsaSignerCertificate));
    signed.addSigner(signerPrivateKeys[1], new IssuerAndSerialNumber(dsaSignerCertificate),
                     (AlgorithmID)AlgorithmID.sha1.clone(),
                     (AlgorithmID)AlgorithmID.dsaWithSHA.clone());


    // a new Thread between the 2 streams
    Writer writer = new Writer(signed, piped_out);
    writer.start();

    // encrypt with DES/CBC and default key length
    SMimeEncrypted encrypted = new SMimeEncrypted(piped_in, contentEA, keyLength);

    // add one RSA recipient
    encrypted.addRecipient(recipientCertificates[0],
                           (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // add one ESDH recipient
    encrypted.addRecipient(recipientCertificates[1], 
                           (AlgorithmID)AlgorithmID.esdhKeyAgreement.clone(),
                           keyWrapAlg, 
                           keyLength);
    // encrypt and write the data to the output stream
    encrypted.writeTo(os);
    // finished
    os.close();
    // get the signed and encrypted message from the ByteArrayOutputStream
    signed_encrpyted_message = os.toByteArray();

    // and now decrypt the data and verify the signature
    is = new ByteArrayInputStream(signed_encrpyted_message);
    encrypted = new SMimeEncrypted(is);
    // use this private key to decrypt the symmetric key
    encrypted.decryptSymmetricKey(recipientPrivateKeys[recipientIndex], recipientIndex);
    // get the InputStream with the decrypted data
    InputStream data_dec = encrypted.getInputStream();

    // read the signed data from the derypted InputStream
    signed = new SMimeSigned(data_dec);

    // get the InputStream with the signed, plain data
    InputStream data = signed.getInputStream();

    // reset our output stream
    os.reset();
    // write the decrypted and verified data to the output stream
    // copy the data
    Util.copyStream(data, os, null);
    os.close();

    // now verify the signed data and print the certificate of the signer
    // (verify() verifies signer at index 0)
    X509Certificate cert = signed.verify();
    System.out.println("Signature OK from: "+cert.getSubjectDN());
    // verify our second test signer
    cert = signed.verify(1);
    System.out.println("Signature OK from: "+cert.getSubjectDN());

    // original and 'received' message must be the same
    if (!CryptoUtils.equalsBlock(buffer, os.toByteArray()))
      throw new RuntimeException("Error: messages are not equal!");
  }
  
  /**
   * Starts the demo.
   */
  public void start() {
    try {
      // read keys and certificates from demo keystore  
      setupCertificates();

      System.out.println("testing an implicit S/MIME signed message...");
      testSMimeSigned(SMimeSigned.IMPLICIT);

      System.out.println("testing an explicit S/MIME signed message...");
      testSMimeSigned(SMimeSigned.EXPLICIT);
      
      AlgorithmID contentEA =  (AlgorithmID)AlgorithmID.des_EDE3_CBC.clone();
      AlgorithmID keyWrapAlg = (AlgorithmID)AlgorithmID.cms_3DES_wrap.clone();
      System.out.println("testing a S/MIME encrypted message for 3DES CBC; decrypting for RSA user...");
      testSMimeEncrypted(contentEA, keyWrapAlg, -1, 0);
      System.out.println("testing a S/MIME encrypted message for 3DES CBC; decrypting for ESDH user...");
      testSMimeEncrypted(contentEA, keyWrapAlg, -1, 1);
      
      contentEA = (AlgorithmID)AlgorithmID.rc2_CBC.clone();
      keyWrapAlg = (AlgorithmID)AlgorithmID.cms_rc2_wrap.clone();
      System.out.println("testing a S/MIME encrypted message for RC2 CBC; decrypting for RSA user...");
      testSMimeEncrypted(contentEA, keyWrapAlg, 128, 0);
      System.out.println("testing a S/MIME encrypted message for RC2 CBC; decrypting for ESDH user...");
      testSMimeEncrypted(contentEA, keyWrapAlg, 128, 1);
      
      contentEA = (AlgorithmID)AlgorithmID.des_EDE3_CBC.clone();
      keyWrapAlg = (AlgorithmID)AlgorithmID.cms_3DES_wrap.clone();
      System.out.println("testing a S/MIME signed and encrypted message for 3DES CBC; decrypting for RSA user...");
   	  testSMimeSignedAndEncrypted(contentEA, keyWrapAlg, -1, 0);
   	  System.out.println("testing a S/MIME signed and encrypted message for 3DES CBC; decrypting for ESDH user...");
   	  testSMimeSignedAndEncrypted(contentEA, keyWrapAlg, -1, 1);
   	  
   	  contentEA = (AlgorithmID)AlgorithmID.rc2_CBC.clone();
   	  keyWrapAlg = (AlgorithmID)AlgorithmID.cms_rc2_wrap.clone();
      System.out.println("testing a S/MIME signed and encrypted message for RC2 CBC; decrypting for RSA user...");
   	  testSMimeSignedAndEncrypted(contentEA, keyWrapAlg, 128, 0);
   	  System.out.println("testing a S/MIME signed and encrypted message for RC2 CBC; decrypting for ESDH user...");
   	  testSMimeSignedAndEncrypted(contentEA, keyWrapAlg, 128, 1);


   	} catch (Exception ex) {
   	  ex.printStackTrace();
   	  throw new RuntimeException(ex.toString());
   	}
  }

  /**
   * The main method.
   * Reads the certificates and the private key and then starts the demos.
   */
  public static void main(String[] argv) throws IOException {

    DemoSMimeUtil.initDemos();
    (new CMSStreamDemo()).start();

    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }

  /**
   * Inner class for copying data between the 2 streams.
   */
  static class Writer extends Thread {

    SMimeSigned signed;
    OutputStream os;
    Exception exception;

    public Writer(SMimeSigned signed, OutputStream os) {
      super("Writer");
      this.signed = signed;
      this.os = os;
    }

    /**
     * Writes the SMimeSinged to the OutputStream.
     */
    public void run() {
      try {
        signed.writeTo(os);
        os.close();
      } catch (Exception ex) {
        exception = ex;
        System.out.println("Writer exception: "+exception);
      }
    }

    /**
     * Returns a possible exception.
     */
    public Exception getException() {
      return exception;
    }
  }
}
