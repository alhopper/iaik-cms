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
// $Header: /IAIK-CMS/current/src/demo/smime/ecc/SMimeEccDemo.java 22    23.08.13 14:32 Dbratko $
// $Revision: 22 $
//

package demo.smime.ecc;

import iaik.asn1.structures.AlgorithmID;
import iaik.cms.CMSAlgorithmID;
import iaik.smime.EncryptedContent;
import iaik.smime.SMimeBodyPart;
import iaik.smime.SMimeException;
import iaik.smime.SMimeMultipart;
import iaik.smime.SignedContent;
import iaik.x509.X509Certificate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Date;

import javax.activation.DataHandler;
import javax.activation.FileDataSource;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;

import demo.DemoSMimeUtil;
import demo.DemoUtil;
import demo.cms.ecc.ECCDemoUtil;
import demo.cms.ecc.keystore.CMSEccKeyStore;
import demo.smime.DumpMessage;

/**
 * This class demonstrates the usage of the IAIK S/MIME implementation to create
 * ECDSA (with SHA1, SHA224, SHA256, SHA384, SHA512, RIPEMD160) signed and/or ECDH based 
 * encrypted S/MIMEv3 messages and how to parse them and verify the signatures 
 * and decrypt the content, respectively.
 * <p>
 * Any keys/certificates required for this demo are read from a keystore
 * file "cmsecc.keystore" located in your current working directory. If
 * the keystore file does not exist you can create it by running the
 * {@link demo.cms.ecc.keystore.SetupCMSEccKeyStore SetupCMSEccKeyStore}
 * program. 
 * <br>
 * Additaionally to <code>iaik_cms.jar</code> you also must have 
 * <code>iaik_jce_(full).jar</code> (IAIK-JCE, <a href =
 * "http://jce.iaik.tugraz.at/sic/products/core_crypto_toolkits/jca_jce">
 * http://jce.iaik.tugraz.at/sic/products/core_crypto_toolkits/jca_jce</a>)
 * and <code>iaik_ecc.jar</code> (IAIK-ECC, <a href =
 * "http://jce.iaik.tugraz.at/sic/products/core_crypto_toolkits/ecc">
 * http://jce.iaik.tugraz.at/sic/products/core_crypto_toolkits/ecc</a>)
 * in your classpath.
 * <p>
 * To run this demo the following packages are required:
 * <ul>
 *    <li>
 *       <code>mail.jar</code>: Get it from <a href="http://www.oracle.com/technetwork/java/javamail/index.html">JavaMail</a>.
 *    </li>   
 *    <li>
 *       <code>activation.jar</code> (required for JDK versions < 1.6): Get it from <a href="http://www.oracle.com/technetwork/java/javase/downloads/index-135046.html">Java Activation Framework</a>.
 *    </li> 
 * </ul>
 * 
 * @see demo.cms.ecc.keystore.SetupCMSEccKeyStore
 * @see iaik.smime.SignedContent
 * @see iaik.smime.EncryptedContent
 * 
 * @author Dieter Bratko
 */
public class SMimeEccDemo {
    
  // whether to print dump all generates test messages to System.out
  final static boolean PRINT_MESSAGES = false;   

  String firstName = "John";
  String lastName = "SMime";
  String to = "smimetest@iaik.tugraz.at";     // email recipient
  String from = "smimetest@iaik.tugraz.at";   // email sender
  String host = "mailhost";                       // name of the mailhost

  X509Certificate[] signerCertificates;          // list of certificates to include in the S/MIME message
  X509Certificate recipientCertificate;          // certificate of the recipient
  X509Certificate signerCertificate;             // certificate of the signer/sender
  X509Certificate encryptionCertOfSigner;        // signer uses different certificate for encryption
  // we use the same signer key for all demos here; in practice you should use a curve
  // matching the security of the hash algorithm used by the signature algorithm
  PrivateKey signerPrivateKey;                   // private key of the signer/sender
  
  
  
  /**
   * Default constructor. Reads certificates and keys from the demo keystore.
   */
  public SMimeEccDemo() {
    
    System.out.println();
    System.out.println("********************************************************************************************");
    System.out.println("*                                SMimeEccDemo demo                                         *");
    System.out.println("* (shows how to create and parse (verify, decrypt) signed and encrypted S/MIMEv3 messages  *");
    System.out.println("*                 using ECDSA for signing and ECDH for key agreement)                      *");
    System.out.println("********************************************************************************************");
    System.out.println();
    
    // get the certificates from the KeyStore
    signerCertificates = CMSEccKeyStore.getCertificateChain(CMSEccKeyStore.ECDSA, CMSEccKeyStore.SZ_256_SIGN);
    signerCertificate = signerCertificates[0];
    signerPrivateKey = CMSEccKeyStore.getPrivateKey(CMSEccKeyStore.ECDSA, CMSEccKeyStore.SZ_256_SIGN);
    

    // recipient 
    recipientCertificate = CMSEccKeyStore.getCertificateChain(CMSEccKeyStore.ECDH, CMSEccKeyStore.SZ_256_CRYPT)[0];
    PrivateKey recipientKey = CMSEccKeyStore.getPrivateKey(CMSEccKeyStore.ECDH, CMSEccKeyStore.SZ_256_CRYPT);
    DumpMessage.privateKey = recipientKey;
    
    // encryption cert of signer (in practice we will not use different key lenghts for recipients)
    encryptionCertOfSigner = CMSEccKeyStore.getCertificateChain(CMSEccKeyStore.ECDH, CMSEccKeyStore.SZ_256_CRYPT_)[0];
  }
  
  /**
   * Starts the demo.
   *
   * @exception IOException if an I/O related error occurs
   */
  public void start() throws IOException {
    
    // get the default Session
  	Session session = DemoSMimeUtil.getSession();

  	try {
      // Create a demo Multipart
      MimeBodyPart mbp1 = new SMimeBodyPart();
	  mbp1.setText("This is a Test of the IAIK S/MIME implementation!\n\n");
	  // attachment
      MimeBodyPart attachment = new SMimeBodyPart();
      attachment.setDataHandler(new DataHandler(new FileDataSource("test.html")));
      attachment.setFileName("test.html");

      Multipart mp = new SMimeMultipart();
      mp.addBodyPart(mbp1);
      mp.addBodyPart(attachment);
      DataHandler multipart = new DataHandler(mp, mp.getContentType());

      Message msg;    // the message to send
      ByteArrayOutputStream baos = new ByteArrayOutputStream(); // we write to a stream
      ByteArrayInputStream bais;  // we read from a stream

      // ECDSA with SHA-1 (ANSI X9.62)
      
      // This is an explicitly signed message (ecdsa-sha1)
      AlgorithmID hashAlgorithm = AlgorithmID.sha1;
      AlgorithmID signatureAlgorithm = CMSAlgorithmID.ecdsa_With_SHA1;
      msg = createSignedMessage(session, multipart, false, hashAlgorithm, signatureAlgorithm);
      System.out.println("creating explicitly signed message " + signatureAlgorithm.getName() + "...");
      baos.reset();
	  msg.saveChanges(); 
	  msg.writeTo(baos);

	  bais = new ByteArrayInputStream(baos.toByteArray());
	  msg = new MimeMessage(null, bais);
	  if (PRINT_MESSAGES) {
        printMessage(msg);
      }
	  DumpMessage.dump(msg);
	  
	  System.out.println("\n\n*****************************************\n\n");


      // This is an implicitly signed message (ecdsa-sha1)
      msg = createSignedMessage(session, multipart, true, hashAlgorithm, signatureAlgorithm);
      System.out.println("creating implicitly signed message " + signatureAlgorithm.getName() + "...");
	  baos.reset();
	  msg.saveChanges(); 
	  msg.writeTo(baos);
     
	  bais = new ByteArrayInputStream(baos.toByteArray());
	  msg = new MimeMessage(null, bais);
	  if (PRINT_MESSAGES) {
        printMessage(msg);
      }
	  DumpMessage.dump(msg);
	  
	  System.out.println("\n\n*****************************************\n\n");
      
      
      
      // ECDSA with SHA-224 (ANSI X9.62)
      
      // This is an explicitly signed message (ecdsa-sha224)
      hashAlgorithm = CMSAlgorithmID.sha224;
      signatureAlgorithm = CMSAlgorithmID.ecdsa_With_SHA224;
      msg = createSignedMessage(session, multipart, false, hashAlgorithm, signatureAlgorithm);
      System.out.println("creating explicitly signed message " + signatureAlgorithm.getName() + "...");
      baos.reset();
      msg.saveChanges(); 
      msg.writeTo(baos);
   
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.dump(msg);
      
      System.out.println("\n\n*****************************************\n\n");


      // This is an implicitly signed message (ecdsa-sha224)
      msg = createSignedMessage(session, multipart, true, hashAlgorithm, signatureAlgorithm);
      System.out.println("creating implicitly signed message " + signatureAlgorithm.getName() + "...");
      baos.reset();
      msg.saveChanges(); 
      msg.writeTo(baos);
      
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.dump(msg);
      
      System.out.println("\n\n*****************************************\n\n");
      
      
      // ECDSA with SHA-256 (ANSI X9.62)
      
      // This is an explicitly signed message (ecdsa-sha256)
      hashAlgorithm = AlgorithmID.sha256;
      signatureAlgorithm = CMSAlgorithmID.ecdsa_With_SHA256;
      msg = createSignedMessage(session, multipart, false, hashAlgorithm, signatureAlgorithm);
      System.out.println("creating explicitly signed message " + signatureAlgorithm.getName() + "...");
      baos.reset();
      msg.saveChanges(); 
      msg.writeTo(baos);
    
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.dump(msg);
      
      System.out.println("\n\n*****************************************\n\n");


      // This is an implicitly signed message (ecdsa-sha256)
      msg = createSignedMessage(session, multipart, true, hashAlgorithm, signatureAlgorithm);
      System.out.println("creating implicitly signed message " + signatureAlgorithm.getName() + "...");
      baos.reset();
      msg.saveChanges(); 
      msg.writeTo(baos);
     
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.dump(msg);
      
      System.out.println("\n\n*****************************************\n\n");

      
      // ECDSA with SHA-384 (ANSI X9.62)
      
      // This is an explicitly signed message (ecdsa-sha384)
      hashAlgorithm = AlgorithmID.sha384;
      signatureAlgorithm = CMSAlgorithmID.ecdsa_With_SHA384;
      msg = createSignedMessage(session, multipart, false, hashAlgorithm, signatureAlgorithm);
      System.out.println("creating explicitly signed message " + signatureAlgorithm.getName() + "...");
      baos.reset();
      msg.saveChanges(); 
      msg.writeTo(baos);
 
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.dump(msg);
      
      System.out.println("\n\n*****************************************\n\n");


      // This is an implicitly signed message (ecdsa-sha384)
      msg = createSignedMessage(session, multipart, true, hashAlgorithm, signatureAlgorithm);
      System.out.println("creating implicitly signed message " + signatureAlgorithm.getName() + "...");
      baos.reset();
      msg.saveChanges(); 
      msg.writeTo(baos);
      
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.dump(msg);
      
      System.out.println("\n\n*****************************************\n\n");
      
      
      // ECDSA with SHA-512 (ANSI X9.62)
      
      // This is an explicitly signed message (ecdsa-sha512)
      hashAlgorithm = AlgorithmID.sha512;
      signatureAlgorithm = CMSAlgorithmID.ecdsa_With_SHA512;
      msg = createSignedMessage(session, multipart, false, hashAlgorithm, signatureAlgorithm);
      System.out.println("creating explicitly signed message " + signatureAlgorithm.getName() + "...");
      baos.reset();
      msg.saveChanges(); 
      msg.writeTo(baos);
     
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.dump(msg);
      
      System.out.println("\n\n*****************************************\n\n");


      // This is an implicitly signed message (ecdsa-sha512)
      msg = createSignedMessage(session, multipart, true, hashAlgorithm, signatureAlgorithm);
      System.out.println("creating implicitly signed message " + signatureAlgorithm.getName() + "...");
      baos.reset();
      msg.saveChanges(); 
      msg.writeTo(baos);
      
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.dump(msg);
      
      System.out.println("\n\n*****************************************\n\n");
      
      
      
      // ECDSA with RIPEMD-160 (plain format, BSI)
      
      // This is an explicitly signed message (ecdsa-plain-ripemd160)
      hashAlgorithm = AlgorithmID.ripeMd160;
      signatureAlgorithm = CMSAlgorithmID.ecdsa_plain_With_RIPEMD160;
      msg = createSignedMessage(session, multipart, false, hashAlgorithm, signatureAlgorithm);
      System.out.println("creating explicitly signed message " + signatureAlgorithm.getName() + "...");
      baos.reset();
      msg.saveChanges(); 
      msg.writeTo(baos);
    
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.dump(msg);
      
      System.out.println("\n\n*****************************************\n\n");


      // This is an implicitly signed message (ecdsa-plain-ripemd160)
      msg = createSignedMessage(session, multipart, true, hashAlgorithm, signatureAlgorithm);
      System.out.println("creating implicitly signed message " + signatureAlgorithm.getName() + "...");
      baos.reset();
      msg.saveChanges(); 
      msg.writeTo(baos);
      
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.dump(msg);
      
      System.out.println("\n\n*****************************************\n\n");
     


      // Now create encrypted messages with different content encryption algorithms
	  
      msg = createEncryptedMessage(session, 
                                   (AlgorithmID)AlgorithmID.rc2_CBC.clone(),
                                   128,
                                   (CMSAlgorithmID)CMSAlgorithmID.dhSinglePass_stdDH_sha1kdf_scheme.clone(),
                                   (AlgorithmID)AlgorithmID.cms_rc2_wrap.clone(),
                                   128);
      System.out.println("creating encrypted message [RC2/128]...");
	  baos.reset();
	  msg.saveChanges(); 
	  msg.writeTo(baos);
      
	  bais = new ByteArrayInputStream(baos.toByteArray());
	  msg = new MimeMessage(null, bais);
	  if (PRINT_MESSAGES) {
        printMessage(msg);
      }
	  DumpMessage.dump(msg);
	  
	  
	  System.out.println("\n\n*****************************************\n\n");
	  
      msg = createEncryptedMessage(session, 
                                   (AlgorithmID)AlgorithmID.des_EDE3_CBC.clone(), 
                                   192,
                                   (CMSAlgorithmID)CMSAlgorithmID.dhSinglePass_stdDH_sha1kdf_scheme.clone(), 
                                   (AlgorithmID)AlgorithmID.cms_3DES_wrap.clone(), 
                                   192);
      System.out.println("creating encrypted message [TripleDES]...");
	  baos.reset();
	  msg.saveChanges(); 
	  msg.writeTo(baos);
      
	  bais = new ByteArrayInputStream(baos.toByteArray());
	  msg = new MimeMessage(null, bais);
	  if (PRINT_MESSAGES) {
        printMessage(msg);
      }
	  DumpMessage.dump(msg);
	  
	  System.out.println("\n\n*****************************************\n\n");
      if (DemoUtil.getIaikProviderVersion() >= 3.14) {
        // AES key wrap available since IAIK-JCE 3.14
        msg = createEncryptedMessage(session, 
                                     (AlgorithmID)AlgorithmID.aes128_CBC.clone(), 
                                     128,
                                     (CMSAlgorithmID)CMSAlgorithmID.dhSinglePass_stdDH_sha1kdf_scheme.clone(),  
                                     (AlgorithmID)CMSAlgorithmID.cms_aes128_wrap.clone(), 
                                     128);
        System.out.println("creating encrypted message [AES]...");
        baos.reset();
        msg.saveChanges(); 
        msg.writeTo(baos);
       
        bais = new ByteArrayInputStream(baos.toByteArray());
        msg = new MimeMessage(null, bais);
        if (PRINT_MESSAGES) {
          printMessage(msg);
        }
        DumpMessage.dump(msg);
        
        System.out.println("\n\n*****************************************\n\n");
      }
      
      
      // signed (ecdsa-sha1) + encrypted 
      
      // Now create implicitly signed and encrypted message with attachment
      hashAlgorithm = AlgorithmID.sha1;
      signatureAlgorithm = CMSAlgorithmID.ecdsa_With_SHA1;
      msg = createSignedAndEncryptedMessage(session, multipart, true, hashAlgorithm, signatureAlgorithm);
      System.out.println("creating implicitly signed " + signatureAlgorithm.getName() + " and encrypted message [RC2/128]...");
	  baos.reset();
	  msg.saveChanges(); 
	  msg.writeTo(baos);
     
	  bais = new ByteArrayInputStream(baos.toByteArray());
	  msg = new MimeMessage(null, bais);
	  if (PRINT_MESSAGES) {
        printMessage(msg);
      }
	  DumpMessage.dump(msg);
	  
	  System.out.println("\n\n*****************************************\n\n");

      // Now create a explicitly signed and encrypted message with attachment
      msg = createSignedAndEncryptedMessage(session, multipart, false, hashAlgorithm, signatureAlgorithm);
      System.out.println("creating explicitly signed " + signatureAlgorithm.getName() + " and encrypted message [RC2/128]...");
	  baos.reset();
	  msg.saveChanges();
	  msg.writeTo(baos);
     
	  bais = new ByteArrayInputStream(baos.toByteArray());
	  msg = new MimeMessage(null, bais);
	  if (PRINT_MESSAGES) {
        printMessage(msg);
      }
	  DumpMessage.dump(msg);
	  System.out.println("\n\n*****************************************\n\n");
      
     
      // ECDSA with SHA-2 not available for IAIK-ECC versions < 2.16
    
      // signed (ecdsa-sha224) + encrypted 
      
      // Now create implicitly signed and encrypted message with attachment
      hashAlgorithm = CMSAlgorithmID.sha224;
      signatureAlgorithm = CMSAlgorithmID.ecdsa_With_SHA224;
      msg = createSignedAndEncryptedMessage(session, multipart, true, hashAlgorithm, signatureAlgorithm);
      System.out.println("creating implicitly signed " + signatureAlgorithm.getName() + " and encrypted message [RC2/128]...");
      baos.reset();
      msg.saveChanges();
      msg.writeTo(baos);
      
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.dump(msg);
      
      System.out.println("\n\n*****************************************\n\n");

      // Now create a explicitly signed and encrypted message with attachment
      msg = createSignedAndEncryptedMessage(session, multipart, false, hashAlgorithm, signatureAlgorithm);
      System.out.println("creating explicitly signed " + signatureAlgorithm.getName() + " and encrypted message [RC2/128]...");
      baos.reset();
      msg.saveChanges(); 
      msg.writeTo(baos);
  
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.dump(msg);
      System.out.println("\n\n*****************************************\n\n");
      
      
      // signed (ecdsa-sha256) + encrypted 
      
      // Now create implicitly signed and encrypted message with attachment
      hashAlgorithm = AlgorithmID.sha256;
      signatureAlgorithm = CMSAlgorithmID.ecdsa_With_SHA256;
      msg = createSignedAndEncryptedMessage(session, multipart, true, hashAlgorithm, signatureAlgorithm);
      System.out.println("creating implicitly signed " + signatureAlgorithm.getName() + " and encrypted message [RC2/128]...");
      baos.reset();
      msg.saveChanges();  
      msg.writeTo(baos);
      
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.dump(msg);
      
      System.out.println("\n\n*****************************************\n\n");

      // Now create a explicitly signed and encrypted message with attachment
      msg = createSignedAndEncryptedMessage(session, multipart, false, hashAlgorithm, signatureAlgorithm);
      System.out.println("creating explicitly signed " + signatureAlgorithm.getName() + " and encrypted message [RC2/128]...");
      baos.reset();
      msg.saveChanges();  
      msg.writeTo(baos);
     
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.dump(msg);
      System.out.println("\n\n*****************************************\n\n");
      
      
      // signed (ecdsa-sha384) + encrypted 
      
      // Now create implicitly signed and encrypted message with attachment
      hashAlgorithm = AlgorithmID.sha384;
      signatureAlgorithm = CMSAlgorithmID.ecdsa_With_SHA384;
      msg = createSignedAndEncryptedMessage(session, multipart, true, hashAlgorithm, signatureAlgorithm);
      System.out.println("creating implicitly signed " + signatureAlgorithm.getName() + " and encrypted message [RC2/128]...");
      baos.reset();
      msg.saveChanges();  
      msg.writeTo(baos);
    
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.dump(msg);
      
      System.out.println("\n\n*****************************************\n\n");

      // Now create a explicitly signed and encrypted message with attachment
      msg = createSignedAndEncryptedMessage(session, multipart, false, hashAlgorithm, signatureAlgorithm);
      System.out.println("creating explicitly signed " + signatureAlgorithm.getName() + " and encrypted message [RC2/128]...");
      baos.reset();
      msg.saveChanges();  
      msg.writeTo(baos);
    
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.dump(msg);
      System.out.println("\n\n*****************************************\n\n");
      
      
      // signed (ecdsa-sha512) + encrypted 
      
      // Now create implicitly signed and encrypted message with attachment
      hashAlgorithm = AlgorithmID.sha512;
      signatureAlgorithm = CMSAlgorithmID.ecdsa_With_SHA512;
      msg = createSignedAndEncryptedMessage(session, multipart, true, hashAlgorithm, signatureAlgorithm);
      System.out.println("creating implicitly signed " + signatureAlgorithm.getName() + " and encrypted message [RC2/128]...");
      baos.reset();
      msg.saveChanges();  
      msg.writeTo(baos);
   
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.dump(msg);
      
      System.out.println("\n\n*****************************************\n\n");

      // Now create a explicitly signed and encrypted message with attachment
      msg = createSignedAndEncryptedMessage(session, multipart, false, hashAlgorithm, signatureAlgorithm);
      System.out.println("creating explicitly signed " + signatureAlgorithm.getName() + " and encrypted message [RC2/128]...");
      baos.reset();
      msg.saveChanges();  
      msg.writeTo(baos);
  
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.dump(msg);
      System.out.println("\n\n*****************************************\n\n");
      
      
      // signed (ecdsa-ripemd160) + encrypted 
      
      // Now create implicitly signed and encrypted message with attachment
      hashAlgorithm = AlgorithmID.ripeMd160;
      signatureAlgorithm = CMSAlgorithmID.ecdsa_plain_With_RIPEMD160;
      msg = createSignedAndEncryptedMessage(session, multipart, true, hashAlgorithm, signatureAlgorithm);
      System.out.println("creating implicitly signed " + signatureAlgorithm.getName() + " and encrypted message [RC2/128]...");
      baos.reset();
      msg.saveChanges();  
      msg.writeTo(baos);
   
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.dump(msg);
      
      System.out.println("\n\n*****************************************\n\n");

      // Now create a explicitly signed and encrypted message with attachment
      msg = createSignedAndEncryptedMessage(session, multipart, false, hashAlgorithm, signatureAlgorithm);
      System.out.println("creating explicitly signed " + signatureAlgorithm.getName() + " and encrypted message [RC2/128]...");
      baos.reset();
      msg.saveChanges();  
      msg.writeTo(baos);
      
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.dump(msg);
      System.out.println("\n\n*****************************************\n\n");
   



  	} catch (Exception ex) {
	  ex.printStackTrace();
	  throw new RuntimeException(ex.toString());
  	}

  	System.out.println("OK!");
  	
  }

  /**
   * Creates a MIME message container with the given subject for the given session.
   * 
   * @param session the mail sesion
   * @param subject the subject of the message
   *
   * @return the MIME message with FROM, TO, DATE and SUBJECT headers (without content)
   *
   * @exception MessagingException if the message cannot be created
   */
  public Message createMessage(Session session, String subject) throws MessagingException {
    MimeMessage msg = new MimeMessage(session);
    msg.setFrom(new InternetAddress(from));
	msg.setRecipients(Message.RecipientType.TO,	InternetAddress.parse(to, false));
	msg.setSentDate(new Date());
    msg.setSubject(subject);
    return msg;
  }
  
  /**
   * Creates a signed and encrypted message.
   *
   * @param session the mail session
   * @param dataHandler the content of the message to be signed and encrypted
   * @param implicit whether to use implicit (application/pkcs7-mime) or explicit
   *                 (multipart/signed) signing
   * @param hashAlgorithm the hash algorithm to be used
   * @param signatureAlgorithm the signature algorithm to be used                
   * 
   * @return the signed and encrypted message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createSignedAndEncryptedMessage(Session session, 
                                                 DataHandler dataHandler,
                                                 boolean implicit,
                                                 AlgorithmID hashAlgorithm,
                                                 AlgorithmID signatureAlgorithm)
    throws MessagingException {

    String subject = null;
    String text = null;
    if (implicit) {
      subject = "IAIK-S/MIME: Implicitly Signed and Encrypted";
      text = "This message is implicitly signed and encrypted!\n\n\n";
    } else {
      subject = "IAIK-S/MIME: Explicitly Signed and Encrypted";
      text = "This message is explicitly signed and encrypted!\n\n\n";
    }
    Message msg = createMessage(session, subject);

    SignedContent sc = new SignedContent(implicit);
    if (dataHandler != null) {
      sc.setDataHandler(dataHandler);
    } else {
      sc.setText(text);
    }
    sc.setCertificates(signerCertificates);
    AlgorithmID ecdsaSig = (AlgorithmID)signatureAlgorithm.clone();
    // CMS-ECC requires that the parameters field is encoded as ASN.1 NULL object (see RFC 3278)
    ecdsaSig.encodeAbsentParametersAsNull(true);
    try {
      sc.addSigner(signerPrivateKey, 
                   signerCertificate, 
                   (AlgorithmID)hashAlgorithm.clone(),
                   ecdsaSig,
                   encryptionCertOfSigner,
                   true);
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Algorithm not supported: " + ex.getMessage(), ex);
    }

    EncryptedContent ec = new EncryptedContent(sc);
    // encrypt for the recipient
    AlgorithmID keyEA = (CMSAlgorithmID)CMSAlgorithmID.dhSinglePass_stdDH_sha1kdf_scheme.clone();
    // the key wrap algorithm to use:
    AlgorithmID keyWrapAlg = (AlgorithmID)AlgorithmID.cms_rc2_wrap.clone();
    // the length of the key encryption key to be generated:
    int kekLength = 128;
    try {  
      ec.addRecipient(recipientCertificate, (AlgorithmID)keyEA.clone(), (AlgorithmID)keyWrapAlg.clone(), kekLength);
    } catch (SMimeException ex) {
      throw new MessagingException("Error adding ECDH recipient: " + ex.getMessage());   
    } 
    try {
      // I want to be able to decrypt the message, too
      ec.addRecipient(encryptionCertOfSigner, (AlgorithmID)keyEA.clone(), (AlgorithmID)keyWrapAlg.clone(), kekLength);
    } catch (SMimeException ex) {
      throw new MessagingException("Error adding ECDH recipient: " + ex.getMessage());   
    }
    // set the encryption algorithm
    try {
      ec.setEncryptionAlgorithm((AlgorithmID)AlgorithmID.rc2_CBC.clone(), 128);
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Content encryption algorithm not supported: " + ex.getMessage());   
    }   
    msg.setContent(ec, ec.getContentType());
    // let the EncryptedContent update some message headers
    ec.setHeaders(msg);

    return msg;
  }
  
  /**
   * Creates a signed message.
   *
   * @param session the mail session
   * @param dataHandler the content of the message to be signed
   * @param implicit whether to use implicit (application/pkcs7-mime) or explicit
   *                 (multipart/signed) signing
   * @param hashAlgorithm the hash algorithm to be used                
   * @param signatureAlgorithm the signature algorithm to be used
   * 
   * @return the signed message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createSignedMessage(Session session, 
                                     DataHandler dataHandler,
                                     boolean implicit,
                                     AlgorithmID hashAlgorithm,
                                     AlgorithmID signatureAlgorithm)
      throws MessagingException {

    String subject = null;
    StringBuffer buf = new StringBuffer();
    
    if (implicit) {
      subject = "IAIK-S/MIME: Implicitly Signed (" + signatureAlgorithm.getName() +")";
      buf.append("This message is implicitly signed with ! " + signatureAlgorithm.getName() + "\n");
      buf.append("You need an S/MIME aware mail client to view this message.\n");
      buf.append("\n\n");
    } else {
      subject = "IAIK-S/MIME: Explicitly Signed (" + signatureAlgorithm.getName() +")";
      buf.append("This message is explicitly signed!\n");
      buf.append("Every mail client can view this message.\n");
      buf.append("Non S/MIME mail clients will show the signature as attachment.\n");
      buf.append("\n\n");
    }
    
    Message msg = createMessage(session, subject);
    
    SignedContent sc = new SignedContent(implicit);
    if (dataHandler != null) {
      sc.setDataHandler(dataHandler);
    } else {
      sc.setText(buf.toString());
    }
    sc.setCertificates(signerCertificates);

    AlgorithmID ecdsaSig = (AlgorithmID)signatureAlgorithm.clone();
    // CMS-ECDSA requires to encode the parameter field as NULL (see RFC 3278)
    ecdsaSig.encodeAbsentParametersAsNull(true);
    try {
      sc.addSigner(signerPrivateKey, 
                   signerCertificate, 
                   (AlgorithmID)hashAlgorithm.clone(),
                   ecdsaSig,
                   encryptionCertOfSigner,
                   true);
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Algorithm not supported: " + ex.getMessage(), ex);
    }

    msg.setContent(sc, sc.getContentType());
    // let the SignedContent update some message headers
    sc.setHeaders(msg);
    return msg;
  }
  
  /**
   * Creates an encrypted message.
   *
   * @param session the mail session
   * @param contentEA the content encryption algorithm to be used
   * @param keyLength the length of the secret content encryption key to be created and used
   * 
   * @return the encrypted message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createEncryptedMessage(Session session, AlgorithmID contentEA, int keyLength,
    AlgorithmID keyEA, AlgorithmID keyWrapAlgorithm, int kekLength)
      throws MessagingException {
    
    AlgorithmID algorithm = (AlgorithmID)contentEA.clone();
    AlgorithmID keyAgreeAlg = (AlgorithmID)keyEA.clone();
    AlgorithmID keyWrapAlg = (AlgorithmID)keyWrapAlgorithm.clone();
    
    StringBuffer subject = new StringBuffer();
    subject.append("IAIK-S/MIME: Encrypted ["+algorithm.getName());
    if (keyLength > 0) {
      subject.append("/"+keyLength);
    }  
    subject.append("]");
    Message msg = createMessage(session, subject.toString());

    EncryptedContent ec = new EncryptedContent();

    StringBuffer buf = new StringBuffer();
    buf.append("This is the encrypted content!\n");
    buf.append("Content encryption algorithm: "+algorithm.getName());
    buf.append("\n\n");

    ec.setText(buf.toString());
    
    try {  
      ec.addRecipient(recipientCertificate, (AlgorithmID)keyAgreeAlg.clone(), (AlgorithmID)keyWrapAlg.clone(), kekLength);
    } catch (SMimeException ex) {
      throw new MessagingException("Error adding ECDH recipient: " + ex.getMessage());   
    }    
    // I want to be able to decrypt the message, too
    try {
      ec.addRecipient(encryptionCertOfSigner, (AlgorithmID)keyAgreeAlg.clone(), (AlgorithmID)keyWrapAlg.clone(), kekLength);
    } catch (SMimeException ex) {
      throw new MessagingException("Error adding ECDH recipient: " + ex.getMessage());   
    }
    try {
      ec.setEncryptionAlgorithm(algorithm, keyLength);
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Content encryption algorithm not supported: " + ex.getMessage());   
    }    

    msg.setContent(ec, ec.getContentType());
    // let the EncryptedContent update some message headers
    ec.setHeaders(msg);

    return msg;
  }
  
  /** 
   * Prints a dump of the given message to System.out.
   *
   * @param msg the message to be dumped to System.out
   *
   * @exception IOException if an I/O error occurs
   */
  private static void printMessage(Message msg) throws IOException {
    System.out.println("------------------------------------------------------------------");
    System.out.println("Message dump: \n");
    try {
      msg.writeTo(System.out);
    } catch (MessagingException ex) {
      throw new IOException(ex.getMessage());   
    }    
    System.out.println("\n------------------------------------------------------------------");
  }  


  /**
   * The main method.
   */
  public static void main(String[] argv) throws Exception {
     
    DemoSMimeUtil.initDemos();
    //  add ECC provider    
    ECCDemoUtil.installIaikEccProvider();
    
   	(new SMimeEccDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
