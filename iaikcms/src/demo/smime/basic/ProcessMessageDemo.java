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
// $Header: /IAIK-CMS/current/src/demo/smime/basic/ProcessMessageDemo.java 13    23.08.13 14:30 Dbratko $
// $Revision: 13 $
//

package demo.smime.basic;

import iaik.asn1.structures.AlgorithmID;
import iaik.cms.CMSAlgorithmID;
import iaik.smime.CompressedContent;
import iaik.smime.EncryptedContent;
import iaik.smime.SMimeBodyPart;
import iaik.smime.SMimeMultipart;
import iaik.smime.SMimeParameters;
import iaik.smime.SignedContent;
import iaik.x509.X509Certificate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
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
import demo.keystore.CMSKeyStore;
import demo.smime.DumpMessage;

/**
 * This class demonstrates the usage of the IAIK S/MIME implementation for 
 * cryptographically processing (e.g. signing or encrypting) a received
 * message. Since the message to be processed has a -- already canonicalized --
 * multipart content, the SMimeMultipart/SMimeBodyPart control can be disabled
 * either globally for the whole application:
 * <pre>
 * SMimeParameters.setCheckForSMimeParts(false);
 * </pre>
 * or only for the specific SignedContent object(s) in use:
 * <pre>
 * SignedContent sc = ...;
 * sc.checkForSMimeParts(false);
 * ...
 * </pre>
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
 * @author Dieter Bratko
 */
public class ProcessMessageDemo {
    
  // whether to print all generates test messages to System.out
  final static boolean PRINT_MESSAGES = true;   

  String firstName = "John";
  String lastName = "SMime";
  String to = "smimetest@iaik.at";               // email recipient
  String from = "smimetest@iaik.at";             // email sender
  String host = "mailhost";                      // name of the mailhost

  X509Certificate[] signerCertificates;          // list of certificates to include in the S/MIME message
  X509Certificate recipientCertificate;          // certificate of the recipient
  X509Certificate signerCertificate;             // certificate of the signer/sender
  X509Certificate encryptionCertOfSigner;        // signer uses different certificate for encryption
  PrivateKey signerPrivateKey;                   // private key of the signer/sender
  
  /**
   * Default constructor. Reads certificates and keys from the demo keystore.
   */
  public ProcessMessageDemo() {
    
    System.out.println();
    System.out.println("******************************************************************************************");
    System.out.println("*                                 ProcessMessageDemo                                     *");
    System.out.println("*      (shows how to cryptographically process (sign, verify) an existing message)       *");
    System.out.println("******************************************************************************************");
    System.out.println();
    
    // get the certificates from the KeyStore
    signerCertificates = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    signerPrivateKey = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    signerCertificate = signerCertificates[0];

    // recipient = signer for this test
    recipientCertificate = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_)[0];
    PrivateKey recipientKey = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_);
    DumpMessage.privateKey = recipientKey;
    encryptionCertOfSigner = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT)[0];
    
    // we will cryptographically process an already existing (canonicalized)
    // message and therefore can disable SMimeMultipart/SMimeBodyPart control
    SMimeParameters.setCheckForSMimeParts(false);
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

      // Create the plain test message
      msg = createPlainMessage(session, multipart);
      System.out.println("creating plain message...");
	    msg.saveChanges();
	    msg.writeTo(baos);
	    bais = new ByteArrayInputStream(baos.toByteArray());
	    msg = new MimeMessage(null, bais);
	    if (PRINT_MESSAGES) {
        printMessage(msg);
      }
	  DumpMessage.dump(msg);
      // the plain message to be crytographically processed
      MimeMessage plainMessage = (MimeMessage)msg;
	  
	    System.out.println("\n\n*****************************************\n\n");
      
      // include RFC822 headers of original message
      boolean includeHeaders = true;
      // This is an explicitly signed message
      msg = createSignedMessage(session, plainMessage, false, includeHeaders);
      System.out.println("creating explicitly signed message...");
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

      // This is an implicitly signed message
      msg = createSignedMessage(session, plainMessage, true, includeHeaders);
      System.out.println("creating implicitly signed message...");
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

      // Now create an encrypted message
      msg = createEncryptedMessage(session, 
                                   plainMessage,
                                   (AlgorithmID)AlgorithmID.des_EDE3_CBC.clone(),
                                   192, 
                                   includeHeaders);
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

      // Now create a implicitly signed and encrypted message with attachment
      msg = createSignedAndEncryptedMessage(session,
                                            plainMessage,
                                            true,
                                            includeHeaders);
      System.out.println("creating implicitly signed and encrypted message [RC2/40]...");
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
      msg = createSignedAndEncryptedMessage(session, plainMessage, false, includeHeaders);
      System.out.println("creating explicitly signed and encrypted message [RC2/40]...");
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
  
  	  // compressed message 
  	  msg = createCompressedMessage(session, 
                                    plainMessage, 
                                    (AlgorithmID)CMSAlgorithmID.zlib_compress.clone(), 
                                    includeHeaders);
  	  System.out.println("creating message with compressed data...");
  	  baos.reset();
  	  msg.saveChanges();
  	  msg.writeTo(baos);
  	  bais = new ByteArrayInputStream(baos.toByteArray());
  	  msg = new MimeMessage(null, bais);
  	  if (PRINT_MESSAGES) {
        printMessage(msg);
      }
  	  DumpMessage.dump(msg);
      
      
      // now the same again but do not include RFC822 headers of original message
      includeHeaders = false;
      // This is an explicitly signed message
      msg = createSignedMessage(session, plainMessage, false, includeHeaders);
      System.out.println("creating explicitly signed message...");
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


      // This is an implicitly signed message
      msg = createSignedMessage(session, plainMessage, true, includeHeaders);
      System.out.println("creating implicitly signed message...");
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

      // Now create an encrypted message
      msg = createEncryptedMessage(session, 
                                   plainMessage, 
                                   (AlgorithmID)AlgorithmID.des_EDE3_CBC.clone(),
                                   192,
                                   includeHeaders);
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

      // Now create a implicitly signed and encrypted message with attachment
      msg = createSignedAndEncryptedMessage(session, plainMessage, true, includeHeaders);
      System.out.println("creating implicitly signed and encrypted message [RC2/40]...");
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
      msg = createSignedAndEncryptedMessage(session, plainMessage, false, includeHeaders);
      System.out.println("creating explicitly signed and encrypted message [RC2/40]...");
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
  
      // compressed message 
      msg = createCompressedMessage(session, 
                                    plainMessage,
                                    (AlgorithmID)CMSAlgorithmID.zlib_compress.clone(),
                                    includeHeaders);
      System.out.println("creating message with compressed data...");
      baos.reset();
      msg.saveChanges();
      msg.writeTo(baos);
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.dump(msg);
  
    } catch (Exception ex) {
  	  ex.printStackTrace();
  	  throw new RuntimeException(ex.toString());
    }
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
   * Creates a simple plain (neither signed nor encrypted) message.
   *
   * @param session the mail session
   * @param dataHandler the content of the message
   * 
   * @return the plain message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createPlainMessage(Session session, DataHandler dataHandler) throws MessagingException {

    Message msg = createMessage(session, "IAIK-S/MIME: Plain message");
    if (dataHandler != null) {
      msg.setDataHandler(dataHandler);
    } else {
      msg.setText("This is a plain message!\nIt is wether signed nor encrypted!\n");
    }
	return msg;
  }
  
  /**
   * Creates a signed and encrypted message.
   *
   * @param session the mail session
   * @param message the message to be signed and encrypted
   * @param implicit whether to use implicit (application/pkcs7-mime) or explicit
   *                 (multipart/signed) signing
   * @param includeHeaders whether to inlcude the RFC822 headers of the original
   *                       message   
   *  
   * @return the signed and encrypted message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createSignedAndEncryptedMessage(Session session, 
                                                 MimeMessage message, 
                                                 boolean implicit,
                                                 boolean includeHeaders)
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
    // set the message content
    if (includeHeaders) {
      sc.setContent(message, message.getContentType());
    } else {
      sc.setDataHandler(message.getDataHandler());
    }
    sc.setCertificates(signerCertificates);
    try {
      sc.addSigner((RSAPrivateKey)signerPrivateKey, signerCertificate);
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Algorithm not supported: " + ex.getMessage(), ex);
    }

    EncryptedContent ec = new EncryptedContent(sc);
    // encrypt for the recipient
    ec.addRecipient(recipientCertificate, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // I want to be able to decrypt the message, too
    ec.addRecipient(encryptionCertOfSigner, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // set the encryption algorithm
    try {
      ec.setEncryptionAlgorithm((AlgorithmID)AlgorithmID.rc2_CBC.clone(), 40);
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
   * @param message the message to be signed
   * @param implicit whether to use implicit (application/pkcs7-mime) or explicit
   *                 (multipart/signed) signing
   * @param includeHeaders whether to inlcude the RFC822 headers of the original
   *                       message
   * 
   * @return the signed message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createSignedMessage(Session session, 
                                     MimeMessage message,
                                     boolean implicit,
                                     boolean includeHeaders)
    throws Exception {

    String subject = null;
    
    if (implicit) {
      subject = "IAIK-S/MIME: Implicitly Signed";
    } else {
      subject = "IAIK-S/MIME: Explicitly Signed";
    }
    
    Message msg = createMessage(session, subject);

    SignedContent sc = new SignedContent(implicit);
    // set message content
    if (includeHeaders) {
      sc.setContent(message, message.getContentType());
    } else {
      sc.setDataHandler(message.getDataHandler());
    }
    sc.setCertificates(signerCertificates);

    try {
      sc.addSigner((RSAPrivateKey)signerPrivateKey, signerCertificate);
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
   * @param message the message to be encrypted
   * @param algorithm the content encryption algorithm to be used
   * @param keyLength the length of the secret content encryption key to be created and used
   * @param includeHeaders whether to inlcude the RFC822 headers of the original
   *                       message 
   * 
   * @return the encrypted message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createEncryptedMessage(Session session, 
                                        MimeMessage message, 
                                        AlgorithmID algorithm, 
                                        int keyLength,
                                        boolean includeHeaders)
    throws MessagingException {

    StringBuffer subject = new StringBuffer();
    subject.append("IAIK-S/MIME: Encrypted ["+algorithm.getName());
    if (keyLength > 0) {
      subject.append("/"+keyLength);
    }  
    subject.append("]");
    Message msg = createMessage(session, subject.toString());

    EncryptedContent ec = new EncryptedContent();
    // set message content
    if (includeHeaders) {
      ec.setContent(message, message.getContentType());
    } else {
      ec.setDataHandler(message.getDataHandler());
    }
    
    // encrypt for the recipient
    ec.addRecipient(recipientCertificate, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // I want to be able to decrypt the message, too
    ec.addRecipient(encryptionCertOfSigner, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
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
   * Creates a compressed message.
   *
   * @param session the mail session
   * @param message the message to be compressed
   * @param algorithm the compression algorithm to be used
   * @param includeHeaders whether to inlcude the RFC822 headers of the original
   *                       message   
   *  
   * @return the compressed message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createCompressedMessage(Session session, 
                                         MimeMessage message,
                                         AlgorithmID algorithm,
                                         boolean includeHeaders)
    throws MessagingException {

    String subject = "IAIK-S/MIME: Compressed ["+algorithm.getName()+"]";
    Message msg = createMessage(session, subject.toString());

    CompressedContent compressedContent = new CompressedContent();
    // set message content
    if (includeHeaders) {
      compressedContent.setContent(message, message.getContentType());
    } else {
      compressedContent.setDataHandler(message.getDataHandler());
    }
    
    try {
      compressedContent.setCompressionAlgorithm(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Compression algorithm not supported: " + ex.getMessage());   
    }   

    msg.setContent(compressedContent, compressedContent.getContentType());
    // let the CompressedContent update some message headers
    compressedContent.setHeaders(msg);

    return msg;
  }
  
    
  
  /** 
   * Prints a dump of the given message to System.out.
   *
   * @param msg the message to be dumped to System.out
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
  public static void main(String[] argv) throws IOException {

    DemoSMimeUtil.initDemos();
   	(new ProcessMessageDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
