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
// $Header: /IAIK-CMS/current/src/demo/cms/signedAndEnvelopedData/SignedAndEnvelopedDataDemo.java 23    23.08.13 14:29 Dbratko $
// $Revision: 23 $
//

package demo.cms.signedAndEnvelopedData;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.cms.EnvelopedData;
import iaik.cms.EnvelopedDataStream;
import iaik.cms.IssuerAndSerialNumber;
import iaik.cms.KeyTransRecipientInfo;
import iaik.cms.RecipientInfo;
import iaik.cms.SignedData;
import iaik.cms.SignedDataStream;
import iaik.cms.SignerInfo;
import iaik.cms.attributes.CMSContentType;
import iaik.cms.attributes.SigningTime;
import iaik.utils.Util;
import iaik.x509.X509Certificate;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.security.PrivateKey;

import demo.DemoUtil;
import demo.keystore.CMSKeyStore;

/**
 * This class shows the sequential combination of the SignedData and EnvelopedData
 * implementations.
 * <p>
 * All keys and certificates are read from a keystore created by the
 * SetupCMSKeyStore program.
 * 
 * @author Dieter Bratko
 */
public class SignedAndEnvelopedDataDemo {

  // signing certificate of user 1
  X509Certificate user1_sign;
  // signing private key of user 1
  PrivateKey user1_sign_pk;
  // encryption certificate of user 1
  X509Certificate user1_crypt;
  // encryption private key of user 1
  PrivateKey user1_crypt_pk;
  // encryption certificate of user 2
  X509Certificate user2_crypt;
  // encryption private key of user 2
  PrivateKey user2_crypt_pk;
  // a certificate chain containing the user certs + CA
  X509Certificate[] certificates;

  /**
   * Setup the demo certificate chains.
   *
   * Keys and certificate are retrieved from the demo KeyStore.
   *
   * @exception IOException if an file read error occurs
   */
  public SignedAndEnvelopedDataDemo() throws IOException {
    
    System.out.println();
    System.out.println("*************************************************************************************************");
    System.out.println("*                               SignedAndEnvelopedDataDemo                                      *");
    System.out.println("* (shows the usage of the combined SignedData(Stream) and EnvelopedData(Stream) implementation) *");
    System.out.println("*************************************************************************************************");
    System.out.println();
    
    // add all certificates to the list
    X509Certificate[] certs = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    user1_sign = certs[0];
    user1_sign_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    user1_crypt = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT)[0];
    user1_crypt_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT);
    user2_crypt = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_)[0];
    user2_crypt_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_);
    // user1 also includes her/his encryption certificate
    certificates = new X509Certificate[certs.length+1];
    System.arraycopy(certs, 0, certificates, 0, certs.length);
    certificates[certs.length] = user1_crypt;

  }

  /**
   * Uses the stream based SignedData and EnvelopedData implementations
   * (<code>SignedDataStream</code>, <code>EnvelopedDataStream</code> to 
   * sign and envelope the given message, encode the CMS object, decodes it 
   * again, removes the envlope and verifies the signature.
   * 
   * @param message the message to be signed and enveloped
   * @exception Exception if an error occurs
   */
  public void testSignedAndEnvelopedDataStream(byte[] message) throws Exception {
    // repository for the signed and enveloped message
    byte[] signed_enveloped_message;
    // the InputStream containing the data to sign and encrypt
    InputStream is = new BufferedInputStream(new ByteArrayInputStream(message));
    // the OutputStream where the data shall be written to
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    OutputStream os = new BufferedOutputStream(out);


    // create an implicit signed message (signature contains message)
    SignedDataStream signed = new SignedDataStream(is, SignedDataStream.IMPLICIT);

    // these certificates are sent within the signature
    signed.setCertificates(certificates);

    // add one signer
    // cert at index 0 is the user certificate
    IssuerAndSerialNumber issuer = new IssuerAndSerialNumber(user1_sign);

    // create a new SignerInfo
    SignerInfo signer_info = new SignerInfo(issuer, AlgorithmID.sha1, user1_sign_pk);
    
    // create some signed attributes
    // the message digest attribute is automatically added
    Attribute[] attributes = new Attribute[2];
    // content type is data
    CMSContentType contentType = new CMSContentType(ObjectID.cms_data);
    attributes[0] = new Attribute(contentType);
    // signing time is now
    SigningTime signingTime = new SigningTime();
    attributes[1] = new Attribute(signingTime);
 
    // set the attributes
    signer_info.setSignedAttributes(attributes);
    // finish the creation of SignerInfo by calling method addSigner
    signed.addSignerInfo(signer_info);

     // we have to sign and encrypt => connect 2 streams
    PipedOutputStream piped_out = new PipedOutputStream();
    PipedInputStream piped_in = new PipedInputStream(piped_out);
    // a new Thread between the 2 streams
    Writer writer = new Writer(signed, piped_out);
    writer.start();

    // encrypt with 3DES/CBC
    EnvelopedDataStream enveloped = new EnvelopedDataStream(piped_in, (AlgorithmID)AlgorithmID.des_EDE3_CBC.clone());
    // add recipients where the symmetric key is encrypted with RSA
        // create the recipient infos
    RecipientInfo[] recipients = new RecipientInfo[2];
    // user1 is the first receiver
    recipients[0] = new KeyTransRecipientInfo(user1_crypt, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // user2 is the second receiver
    recipients[1] = new KeyTransRecipientInfo(user2_crypt, (AlgorithmID)AlgorithmID.rsaEncryption.clone());

    // specify the recipients of the encrypted message
    enveloped.setRecipientInfos(recipients);

    // encrypt and write the data to the output stream
    enveloped.writeTo(os,2048);
    // finished
    os.close();
    is.close();
    // get the signed and encrypted message from the ByteArrayOutputStream
    signed_enveloped_message = out.toByteArray();
    System.out.println("Message created, now doing the parsing...");
    // and now decrypt the data and verify the signature
    is = new BufferedInputStream(new ByteArrayInputStream( signed_enveloped_message));
    enveloped = new EnvelopedDataStream(is);
    // use this private key to decrypt the symmetric key of recipient 0
    enveloped.setupCipher(user1_crypt_pk, 0);
    // get the InputStream with the decrypted data
    InputStream data_dec = enveloped.getInputStream();
    System.out.println("Message decrypted!");
    // read the signed data from the decrypted InputStream
    signed = new SignedDataStream(data_dec);
    // get the InputStream with the signed, plain data
    InputStream data = signed.getInputStream();

    // reset our output stream
    out.reset();
    // write the decrypted and verified data to the output stream
    os = new BufferedOutputStream(out);
    // copy the data
    Util.copyStream(data, os, null);
    os.close();
    out.close();
    is.close();
    data_dec.close();

    // now verify the signature of the one and only signer and print the certificate of the signer
    X509Certificate cert = signed.verify(0);
    System.out.println("Signature OK from: "+cert.getSubjectDN());


    System.out.println("Received message: \"" + new String(out.toByteArray())+"\"");
  }
  
  /**
   * Uses the non-stream based SignedData and EnvelopedData implementations
   * (<code>SignedData</code>, <code>EnvelopedData</code> to 
   * sign and envelope the given message, encode the CMS object, decodes it 
   * again, removes the envlope and verifies the signature.
   * 
   * @param message the message to be signed and enveloped
   * @exception Exception if an error occurs
   */
  public void testSignedAndEnvelopedData(byte[] message) throws Exception {
        
    // create an implicit signed message (signature contains message)
    SignedData signed = new SignedData(message, SignedData.IMPLICIT);

    // these certificates are sent within the signature
    signed.setCertificates(certificates);

    // add one signer
    // cert at index 0 is the user certificate
    IssuerAndSerialNumber issuer = new IssuerAndSerialNumber(user1_sign);

    // create a new SignerInfo
    SignerInfo signer_info = new SignerInfo(issuer, (AlgorithmID)AlgorithmID.sha1.clone(), user1_sign_pk);
    
    // create some signed attributes
    // the message digest attribute is automatically added
    Attribute[] attributes = new Attribute[2];
    // content type is data
    CMSContentType contentType = new CMSContentType(ObjectID.cms_data);
    attributes[0] = new Attribute(contentType);
    // signing time is now
    SigningTime signingTime = new SigningTime();
    attributes[1] = new Attribute(signingTime);
 
    // set the attributes
    signer_info.setSignedAttributes(attributes);
    // finish the creation of SignerInfo by calling method addSigner
    signed.addSignerInfo(signer_info);

    // encode SignedData to a byte array
    byte[] signed_message = signed.getEncoded();

    // encrypt with 3DES/CBC
    EnvelopedData enveloped = new EnvelopedData(signed_message, (AlgorithmID)AlgorithmID.des_EDE3_CBC.clone());
    // add recipients where the symmetric key is encrypted with RSA
        // create the recipient infos
    RecipientInfo[] recipients = new RecipientInfo[2];
    // user1 is the first receiver
    recipients[0] = new KeyTransRecipientInfo(user1_crypt, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // user2 is the second receiver
    recipients[1] = new KeyTransRecipientInfo(user2_crypt, (AlgorithmID)AlgorithmID.rsaEncryption.clone());

    // specify the recipients of the encrypted message
    enveloped.setRecipientInfos(recipients);

    // encrypt and write the data to a byte array
    byte[] signed_enveloped_message = enveloped.getEncoded();

    System.out.println("Message created, now doing the parsing...");
    // and now decrypt the data and verify the signature
    InputStream is = new BufferedInputStream(new ByteArrayInputStream(signed_enveloped_message));
    enveloped = new EnvelopedData(is);
    // use this private key to decrypt the symmetric key of recipient 0
    enveloped.setupCipher(user1_crypt_pk, 0);
    // get the InputStream with the decrypted data
    InputStream data_dec = enveloped.getInputStream();
    System.out.println("Message decrypted!");
    // read the signed data from the decrypted InputStream
    signed = new SignedData(data_dec);
    // get the content with the signed, plain data
    byte[] data = signed.getContent();

    // now verify the signature of the one and only signer and print the certificate of the signer
    X509Certificate cert = signed.verify(0);
    System.out.println("Signature OK from: "+cert.getSubjectDN());


    System.out.println("Received message: \"" + new String(data)+"\"");
  }




  /**
   * Starts the test.
   */
  public void start() {
     // the test message
    String m = "This demo message will be signed and/or encrypted.";
    System.out.println("Test message: \""+m+"\"");
    System.out.println();
    byte[] message = m.getBytes();

    try {
      System.out.println("Signed and enveloped data - stream based demo.");
      testSignedAndEnvelopedDataStream(message);
      System.out.println();
      
      System.out.println("Signed and enveloped data - non stream based demo.");
      testSignedAndEnvelopedData(message);
      System.out.println();

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
   *            and certificates from files
   */
  public static void main(String argv[]) throws Exception {

   	demo.DemoUtil.initDemos();

    (new SignedAndEnvelopedDataDemo()).start();
    DemoUtil.waitKey();
  }

  /**
   * Inner class for copying data between the 2 streams.
   */
  static class Writer extends Thread {

    SignedDataStream signed;
    OutputStream os;
    Exception exception;

    public Writer(SignedDataStream signed, OutputStream os) {
      super("Writer");
      this.signed = signed;
      this.os = os;
    }

    /**
     * Writes the SMimeSinged to the OutputStream.
     */
    public void run() {
      try {
        signed.writeTo(os,2048);
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
