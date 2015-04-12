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
// $Header: /IAIK-CMS/current/src/demo/smime/ecc/SMimeEccSuiteBDemo.java 10    23.08.13 14:32 Dbratko $
// $Revision: 10 $
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
 * This class demonstrates the usage of the IAIK S/MIME implementation to create and
 * parse ECDSA signed and/or ECDH based encrypted S/MIMEv3 messages according to 
 * RFC 5008 &quot;Suite B in Secure/Multipurpose Internet Mail Extensions (S/MIME)&quot;.
 * <br>
 * The following algorithms are required by Suite B of the United States Security Agency 
 * (NSA) for use of ECC in S/MIME (see RFC 5008):
 * <pre>
 *                          Security Level 1   Security Level 2
 *                          ----------------   ----------------
 *    Message Digest:       SHA-256            SHA-384
 *    Signature:            ECDSA with P-256   ECDSA with P-384
 *    
 *    
 *
 *                           Security Level 1   Security Level 2
 *                          ----------------   ----------------
 *    Key Agreement:        ECDH with P-256    ECDH with P-384
 *    Key Derivation:       SHA-256            SHA-384
 *    Key Wrap:             AES-128 Key Wrap   AES-256 Key Wrap
 *    Content Encryption:   AES-128 CBC        AES-256 CBC
 * </pre> 
 * <br>
 * The key encryption algorithms used during ECDH are 
 * <code>dhSinglePass-stdDH-sha256kdf-scheme</code> for Security Level 1 and
 * <cdoe>dhSinglePass-stdDH-sha384kdf-scheme</code> for Security Level 2.
 * <p> 
 * Any keys/certificates required for this demo are read from a keystore
 * file "cmsecc.keystore" located in your current working directory. If
 * the keystore file does not exist you can create it by running the
 * {@link demo.cms.ecc.keystore.SetupCMSEccKeyStore SetupCMSEccKeyStore}
 * program. 
 * <br>
 * Additionally to <code>iaik_cms.jar</code> you also must have 
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
public class SMimeEccSuiteBDemo {
    
  // whether to print dump all generates test messages to System.out
  final static boolean PRINT_MESSAGES = true;

  String firstName = "John";
  String lastName = "SMime";
  String to = "smimetest@iaik.tugraz.at";     // email recipient
  String from = "smimetest@iaik.tugraz.at";   // email sender
  String host = "mailhost";                       // name of the mailhost

  // keys and certs for security level 1 demo (256 bit)
  X509Certificate[] signerCertificates1_;          // list of certificates to include in the S/MIME message
  X509Certificate signerCertificate1_;             // certificate of the signer/sender
  X509Certificate recipientCertificate1_;          // certificate of the recipient
  X509Certificate encryptionCertOfSigner1_;        // signer uses different certificate for encryption
  PrivateKey signerPrivateKey1_;                   // private key of the signer/sender
  PrivateKey recipientKey1_;                       // private key of recipient
  
  // keys and certs for security level 2 demo (384 bit)
  X509Certificate[] signerCertificates2_;          // list of certificates to include in the S/MIME message
  X509Certificate signerCertificate2_;             // certificate of the signer/sender
  X509Certificate recipientCertificate2_;          // certificate of the recipient
  X509Certificate encryptionCertOfSigner2_;        // signer uses different certificate for encryption
  PrivateKey signerPrivateKey2_;                   // private key of the signer/sender
  PrivateKey recipientKey2_;                       // private key of recipient
  
  /**
   * Default constructor. Reads certificates and keys from the demo keystore.
   */
  public SMimeEccSuiteBDemo() {
    
    System.out.println();
    System.out.println("********************************************************************************************");
    System.out.println("*                                SMimeEccSuiteBDemo demo                                   *");
    System.out.println("*            (shows how to use NSA Suite B algorithms with ECDSA and ECDH                  *");
    System.out.println("*                          to sign and encrypt S/MIME messages)                            *");
    System.out.println("********************************************************************************************");
    System.out.println();
    
    // get keys and certificates for security level 1 demo from KeyStore
    
    // signer
    signerCertificates1_ = CMSEccKeyStore.getCertificateChain(CMSEccKeyStore.ECDSA, CMSEccKeyStore.SZ_256_SIGN);
    signerCertificate1_ = signerCertificates1_[0];
    signerPrivateKey1_ = CMSEccKeyStore.getPrivateKey(CMSEccKeyStore.ECDSA, CMSEccKeyStore.SZ_256_SIGN);
    // recipient 
    recipientCertificate1_ = CMSEccKeyStore.getCertificateChain(CMSEccKeyStore.ECDH, CMSEccKeyStore.SZ_256_CRYPT)[0];
    recipientKey1_ = CMSEccKeyStore.getPrivateKey(CMSEccKeyStore.ECDH, CMSEccKeyStore.SZ_256_CRYPT);
  
    // encryption cert of signer 
    encryptionCertOfSigner1_ = CMSEccKeyStore.getCertificateChain(CMSEccKeyStore.ECDH, CMSEccKeyStore.SZ_256_CRYPT_)[0];
    
    // get keys and certificates for security level 2 demo from KeyStore
    
    // signer
    signerCertificates2_ = CMSEccKeyStore.getCertificateChain(CMSEccKeyStore.ECDSA, CMSEccKeyStore.SZ_384_SIGN);
    signerCertificate2_ = signerCertificates2_[0];
    signerPrivateKey2_ = CMSEccKeyStore.getPrivateKey(CMSEccKeyStore.ECDSA, CMSEccKeyStore.SZ_384_SIGN);
    // recipient 
    recipientCertificate2_ = CMSEccKeyStore.getCertificateChain(CMSEccKeyStore.ECDH, CMSEccKeyStore.SZ_384_CRYPT)[0];
    recipientKey2_ = CMSEccKeyStore.getPrivateKey(CMSEccKeyStore.ECDH, CMSEccKeyStore.SZ_384_CRYPT);
    // encryption cert of signer 
    encryptionCertOfSigner2_ = CMSEccKeyStore.getCertificateChain(CMSEccKeyStore.ECDH, CMSEccKeyStore.SZ_384_CRYPT_)[0];

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

        
        
      // Suite B Security Level 1 Signature: ECDSA with SHA-256 (ANSI X9.62)
      
      // This is an explicitly signed message (ecdsa-sha256)
      AlgorithmID hashAlgorithm = AlgorithmID.sha256;
      AlgorithmID signatureAlgorithm = CMSAlgorithmID.ecdsa_With_SHA256;
      msg = createSignedMessage(session, 
                                multipart, 
                                false, 
                                hashAlgorithm, 
                                signatureAlgorithm,
                                signerPrivateKey1_,
                                signerCertificates1_,
                                encryptionCertOfSigner1_);
      System.out.println("Suite B, Security Level 1: Creating explicitly signed message " + signatureAlgorithm.getName() + "...");
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
      msg = createSignedMessage(session, 
                                multipart, 
                                true, 
                                hashAlgorithm, 
                                signatureAlgorithm,
                                signerPrivateKey1_,
                                signerCertificates1_,
                                encryptionCertOfSigner1_);
      System.out.println("Suite B, Security Level 1: Creating implicitly signed message " + signatureAlgorithm.getName() + "...");
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

      
      // Suite B Security Level 2 Signature: ECDSA with SHA-384 (ANSI X9.62)
      
      // This is an explicitly signed message (ecdsa-sha384)
      hashAlgorithm = AlgorithmID.sha384;
      signatureAlgorithm = CMSAlgorithmID.ecdsa_With_SHA384;
      msg = createSignedMessage(session, 
                                multipart, 
                                false, 
                                hashAlgorithm, 
                                signatureAlgorithm,
                                signerPrivateKey2_,
                                signerCertificates2_,
                                encryptionCertOfSigner2_);
      System.out.println("Suite B, Security Level 2: Creating explicitly signed message " + signatureAlgorithm.getName() + "...");
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
      msg = createSignedMessage(session, 
                                multipart, 
                                true, 
                                hashAlgorithm,
                                signatureAlgorithm,
                                signerPrivateKey2_,
                                signerCertificates2_,
                                encryptionCertOfSigner2_);
      System.out.println("Suite B, Security Level 2: Creating implicitly signed message " + signatureAlgorithm.getName() + "...");
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
        



      // Now create encrypted messages 
      
      // Suite B Security Level 1 Encryption: ECDH with P-256, AES-128
      
      AlgorithmID contentEncAlg = AlgorithmID.aes128_CBC;
      AlgorithmID keyEncAlg = CMSAlgorithmID.dhSinglePass_stdDH_sha256kdf_scheme;
      AlgorithmID keyWrapAlg = CMSAlgorithmID.cms_aes128_wrap;
      int contentEncKeyLength = 128;
      int keyEncKeyLength = 128;
	  
      msg = createEncryptedMessage(session, 
                                   contentEncAlg, 
                                   contentEncKeyLength,
                                   keyEncAlg, 
                                   keyWrapAlg, 
                                   keyEncKeyLength,
                                   recipientCertificate1_,
                                   encryptionCertOfSigner1_);
      System.out.println("Suite B, Security Level 1: Creating encrypted message [ECDH P-256, AES-128]...");
      baos.reset();
      msg.saveChanges(); 
      msg.writeTo(baos);
     
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.privateKey = recipientKey1_;
      DumpMessage.dump(msg);
      
      System.out.println("\n\n*****************************************\n\n");
      
      
      // Suite B Security Level 2 Encryption: ECDH with P-384, AES-256
      
      contentEncAlg = AlgorithmID.aes256_CBC;
      keyEncAlg = CMSAlgorithmID.dhSinglePass_stdDH_sha384kdf_scheme;
      keyWrapAlg = CMSAlgorithmID.cms_aes256_wrap;
      contentEncKeyLength = 256;
      keyEncKeyLength = 256;
      
      msg = createEncryptedMessage(session, 
                                   contentEncAlg, 
                                   contentEncKeyLength,
                                   keyEncAlg, 
                                   keyWrapAlg, 
                                   keyEncKeyLength,
                                   recipientCertificate2_,
                                   encryptionCertOfSigner2_);
      System.out.println("Suite B, Security Level 2: Creating encrypted message [ECDH P-384, AES-256]...");
      baos.reset();
      msg.saveChanges(); 
      msg.writeTo(baos);
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.privateKey = recipientKey2_;
      DumpMessage.dump(msg);
      
      System.out.println("\n\n*****************************************\n\n");
      
      
        
        
      // signed + encrypted
      
      // Suite B Security Level 1: ECDSA with SHA-256; ECDH with P-256, AES-128
      
      // Now create implicitly signed and encrypted message with attachment
      hashAlgorithm = AlgorithmID.sha256;
      signatureAlgorithm = CMSAlgorithmID.ecdsa_With_SHA256;
      contentEncAlg = AlgorithmID.aes128_CBC;
      keyEncAlg = CMSAlgorithmID.dhSinglePass_stdDH_sha256kdf_scheme;
      keyWrapAlg = CMSAlgorithmID.cms_aes128_wrap;
      contentEncKeyLength = 128;
      keyEncKeyLength = 128;
      msg = createSignedAndEncryptedMessage(session, 
                                            multipart, 
                                            true, 
                                            hashAlgorithm, 
                                            signatureAlgorithm,
                                            signerPrivateKey1_,
                                            signerCertificates1_,
                                            encryptionCertOfSigner1_,
                                            contentEncAlg, 
                                            contentEncKeyLength,
                                            keyEncAlg, 
                                            keyWrapAlg, 
                                            keyEncKeyLength,
                                            recipientCertificate1_);
      System.out.println("Suite B, Security Level 1: Creating implicitly signed " + signatureAlgorithm.getName() + " and encrypted message [ECDH P-256, AES-128]...");
      baos.reset();
      msg.saveChanges(); 
      msg.writeTo(baos);
     
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.privateKey = recipientKey1_;
      DumpMessage.dump(msg);
      
      System.out.println("\n\n*****************************************\n\n");

      // Now create a explicitly signed and encrypted message with attachment
      msg = createSignedAndEncryptedMessage(session, 
                                            multipart, 
                                            false, 
                                            hashAlgorithm, 
                                            signatureAlgorithm,
                                            signerPrivateKey1_,
                                            signerCertificates1_,
                                            encryptionCertOfSigner1_,
                                            contentEncAlg, 
                                            contentEncKeyLength,
                                            keyEncAlg, 
                                            keyWrapAlg, 
                                            keyEncKeyLength,
                                            recipientCertificate1_);
      System.out.println("Suite B, Security Level 1: Creating explicitly signed " + signatureAlgorithm.getName() + " and encrypted message [ECDH P-256, AES-128]...");
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
        
        
      // Suite B Security Level 2: ECDSA with SHA-384; ECDH with P-384, AES-256
      
      // Now create implicitly signed and encrypted message with attachment
      hashAlgorithm = AlgorithmID.sha384;
      signatureAlgorithm = CMSAlgorithmID.ecdsa_With_SHA384;
      contentEncAlg = AlgorithmID.aes256_CBC;
      keyEncAlg = CMSAlgorithmID.dhSinglePass_stdDH_sha384kdf_scheme;
      keyWrapAlg = CMSAlgorithmID.cms_aes256_wrap;
      contentEncKeyLength = 256;
      keyEncKeyLength = 256;
      msg = createSignedAndEncryptedMessage(session, 
                                            multipart, 
                                            true, 
                                            hashAlgorithm, 
                                            signatureAlgorithm,
                                            signerPrivateKey2_,
                                            signerCertificates2_,
                                            encryptionCertOfSigner2_,
                                            contentEncAlg, 
                                            contentEncKeyLength,
                                            keyEncAlg, 
                                            keyWrapAlg, 
                                            keyEncKeyLength,
                                            recipientCertificate2_);
      System.out.println("Suite B, Security Level 1: Creating implicitly signed " + signatureAlgorithm.getName() + " and encrypted message [ECDH P-384, AES-256]...");
      baos.reset();
      msg.saveChanges();
      msg.writeTo(baos);
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.privateKey = recipientKey2_;
      DumpMessage.dump(msg);
      
      System.out.println("\n\n*****************************************\n\n");

      // Now create a explicitly signed and encrypted message with attachment
      msg = createSignedAndEncryptedMessage(session, 
                                            multipart, 
                                            false, 
                                            hashAlgorithm, 
                                            signatureAlgorithm,
                                            signerPrivateKey2_,
                                            signerCertificates2_,
                                            encryptionCertOfSigner2_,
                                            contentEncAlg, 
                                            contentEncKeyLength,
                                            keyEncAlg, 
                                            keyWrapAlg, 
                                            keyEncKeyLength,
                                            recipientCertificate2_);
      System.out.println("Suite B, Security Level 1: Creating explicitly signed " + signatureAlgorithm.getName() + " and encrypted message [ECDH P-384, AES-256]...");
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
   * Creates a signed message.
   *
   * @param session the mail session
   * @param dataHandler the content of the message to be signed
   * @param implicit whether to use implicit (application/pkcs7-mime) or explicit
   *                 (multipart/signed) signing
   * @param hashAlgorithm the hash algorithm to be used                
   * @param signatureAlgorithm the signature algorithm to be used
   * @param signerPrivateKey the private key of the signer
   * @param signerCertificates the certificate chain of the signer
   * @param encryptionCertOfSigner the encryption certificate of the signer
   *                               (to be announced within the SignerInfo)
   * 
   * @return the signed message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createSignedMessage(Session session, 
                                     DataHandler dataHandler,
                                     boolean implicit,
                                     AlgorithmID hashAlgorithm,
                                     AlgorithmID signatureAlgorithm,
                                     PrivateKey signerPrivateKey,
                                     X509Certificate[] signerCertificates,
                                     X509Certificate encryptionCertOfSigner)
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
                   signerCertificates[0], 
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
   * @param keyEA the key encryption algorithm to be used
   * @param keyWrapAlg the key wrap algorithm to be used
   * @param kekLength the length of the key encryption algorithm
   * @param recipientCertificate the encryption certificate of the recipient
   * @param encryptionCertOfSender the encryption certificate of the sender
   * 
   * @return the encrypted message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createEncryptedMessage(Session session, 
                                        AlgorithmID contentEA, 
                                        int keyLength,
                                        AlgorithmID keyEA, 
                                        AlgorithmID keyWrapAlg,
                                        int kekLength,
                                        X509Certificate recipientCertificate,
                                        X509Certificate encryptionCertOfSender)
    throws MessagingException {
    
    StringBuffer subject = new StringBuffer();
    subject.append("IAIK-S/MIME: Encrypted ["+contentEA.getName());
    if (keyLength > 0) {
      subject.append("/"+keyLength);
    }  
    subject.append("]");
    Message msg = createMessage(session, subject.toString());

    EncryptedContent ec = new EncryptedContent();

    StringBuffer buf = new StringBuffer();
    buf.append("This is the encrypted content!\n");
    buf.append("Content encryption algorithm: "+contentEA.getName());
    buf.append("\n\n");

    ec.setText(buf.toString());
    
    try {  
      ec.addRecipient(recipientCertificate, (AlgorithmID)keyEA.clone(), (AlgorithmID)keyWrapAlg.clone(), kekLength);
    } catch (SMimeException ex) {
      throw new MessagingException("Error adding ECDH recipient: " + ex.getMessage());   
    }    
    // Sender want to be able to decrypt the message, too
    try {
      ec.addRecipient(encryptionCertOfSender, (AlgorithmID)keyEA.clone(), (AlgorithmID)keyWrapAlg.clone(), kekLength);
    } catch (SMimeException ex) {
      throw new MessagingException("Error adding ECDH recipient: " + ex.getMessage());   
    }
    try {
      ec.setEncryptionAlgorithm((AlgorithmID)contentEA.clone(), keyLength);
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Content encryption algorithm not supported: " + ex.getMessage());   
    }    

    msg.setContent(ec, ec.getContentType());
    // let the EncryptedContent update some message headers
    ec.setHeaders(msg);

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
   * @param signerPrivateKey the private key of the signer
   * @param signerCertificates the certificate chain of the signer
   * @param encryptionCertOfSigner the encryption certificate of the signer
   *                               (to be announced within the SignerInfo)
   * @param contentEA the content encryption algorithm to be used
   * @param keyLength the length of the secret content encryption key to be created and used
   * @param keyEA the key encryption algorithm to be used
   * @param keyWrapAlgorithm the key wrap algorithm to be used
   * @param kekLength the length of the key encryption algorithm
   * @param recipientCertificate the encryption certificate of the recipient
   * 
   * @return the signed and encrypted message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createSignedAndEncryptedMessage(Session session, 
                                                 DataHandler dataHandler,
                                                 boolean implicit,
                                                 AlgorithmID hashAlgorithm,
                                                 AlgorithmID signatureAlgorithm,
                                                 PrivateKey signerPrivateKey,
                                                 X509Certificate[] signerCertificates,
                                                 X509Certificate encryptionCertOfSigner, 
                                                 AlgorithmID contentEA, 
                                                 int keyLength,
                                                 AlgorithmID keyEA, 
                                                 AlgorithmID keyWrapAlgorithm,
                                                 int kekLength,
                                                 X509Certificate recipientCertificate)
    throws MessagingException {

    String subject = null;
    String text = null;
    if (implicit) {
      subject = "IAIK-S/MIME: Implicitly Signed (" + signatureAlgorithm.getName() + ") and Encrypted (" + contentEA.getName() + ")";
      text = "This message is implicitly signed (" + signatureAlgorithm.getName() + ") and Encrypted (" + contentEA.getName() + ")!\n\n\n";
    } else {
      subject = "IAIK-S/MIME: Explicitly Signed (" + signatureAlgorithm.getName() + ") and Encrypted (" + contentEA.getName() + ")";
      text = "This message is explicitly signed (" + signatureAlgorithm.getName() + ") and Encrypted (" + contentEA.getName() + ")!\n\n\n";
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
                   signerCertificates[0], 
                   (AlgorithmID)hashAlgorithm.clone(),
                   ecdsaSig,
                   encryptionCertOfSigner,
                   true);
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Algorithm not supported: " + ex.getMessage(), ex);
    }

    EncryptedContent ec = new EncryptedContent(sc);
    // encrypt for the recipient
    try {  
      ec.addRecipient(recipientCertificate, (AlgorithmID)keyEA.clone(), (AlgorithmID)keyWrapAlgorithm.clone(), kekLength);
    } catch (SMimeException ex) {
      throw new MessagingException("Error adding ECDH recipient: " + ex.getMessage());   
    } 
    try {
      // I want to be able to decrypt the message, too
      ec.addRecipient(encryptionCertOfSigner, (AlgorithmID)keyEA.clone(), (AlgorithmID)keyWrapAlgorithm.clone(), kekLength);
    } catch (SMimeException ex) {
      throw new MessagingException("Error adding ECDH recipient: " + ex.getMessage());   
    }
    // set the encryption algorithm
    try {
      ec.setEncryptionAlgorithm(contentEA, keyLength);
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
    // add ECC provider    
    ECCDemoUtil.installIaikEccProvider();
   	(new SMimeEccSuiteBDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
