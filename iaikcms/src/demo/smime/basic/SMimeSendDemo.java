// Copyright (C) 2002 IAIK
// http://jce.iaik.at
//
// Copyright (C) 2003 Stiftung Secure Information and 
//                    Communication Technologies SIC
// http://www.sic.st
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
// $Header: /IAIK-CMS/current/src/demo/smime/basic/SMimeSendDemo.java 33    23.08.13 14:30 Dbratko $
// $Revision: 33 $
//

package demo.smime.basic;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Name;
import iaik.pkcs.PKCSException;
import iaik.pkcs.pkcs10.CertificateRequest;
import iaik.smime.EncryptedContent;
import iaik.smime.PKCS10Content;
import iaik.smime.SMimeBodyPart;
import iaik.smime.SMimeMultipart;
import iaik.smime.SMimeParameters;
import iaik.smime.SignedContent;
import iaik.x509.X509Certificate;

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
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import demo.DemoSMimeUtil;
import demo.DemoUtil;
import demo.keystore.CMSKeyStore;

/**
 * This class demonstrates the usage of the IAIK S/MIME implementation for sending
 * signed and/or encryped emails based on the JavaMail API. 
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
 * <b>Usage:</b>
 * <pre>
 * SMimeSend [-H host] [-S sender name] [-F (From) sender address] [-T (To) recipient address]
 * </pre>
 * <b>Example</b>:
 * <pre>
 * SMimeSend -H mailhost -S \"John SMime\" -F smimetest@iaik.tugraz.at -T smimetest@iaik.tugraz.at
 * </pre>
 * By default this demo used "mailhost" as host, "John SMime" as sender name, and "smimetest@iaik.tugraz.at"
 * as sender and also as recipient mail address. "smimetest@iaik.tugraz.at" is also the email address
 * contained in the demo certificates. Although you should specify other email addresses to send
 * the test messages to yourself, be aware that the certificate email check may fail on the
 * receiving side ({@link SMimeShowDemo SMimeShowDemo}).
 *
 * @see iaik.smime.EncryptedContent
 * @see iaik.smime.SignedContent
 */
public class SMimeSendDemo {

  String senderName_ = "John SMime";
  String to_ = "smimetest@iaik.tugraz.at";     // email recipient
  String from_ = "smimetest@iaik.tugraz.at";   // email sender
  String host_ = "mailhost";                   // name of the mailhost

  X509Certificate[] signerCertificates_;    // list of certificates to include in the S/MIME message
  X509Certificate recipientCertificate_;    // certificate of the recipient
  X509Certificate signerCertificate_;       // certificate of the signer/sender
  X509Certificate encryptionCertOfSigner_;  // signer uses different certificate for encryption
  PrivateKey signerPrivateKey_;             // private key of the signer/sender
  
  /**
   * Default constructor. Reads certificates and keys from the demo keystore.
   */
  public SMimeSendDemo() {
    
    System.out.println();
    System.out.println("******************************************************************************************");
    System.out.println("*                                 SMimeSend demo                                         *");
    System.out.println("*         (shows how to create and send signed and encrypted S/MIME messages)            *");
    System.out.println("******************************************************************************************");
    System.out.println();
    
    // get the certificates from the KeyStore
    signerCertificates_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    signerPrivateKey_ = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    signerCertificate_ = signerCertificates_[0];

    // recipient = signer for this test
    recipientCertificate_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_)[0];
    encryptionCertOfSigner_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT)[0];
    
    // send the encryption cert of the signer along with the signer certificates
    X509Certificate[] tmpCerts = new X509Certificate[signerCertificates_.length + 1];
    System.arraycopy(signerCertificates_, 0, tmpCerts, 0, signerCertificates_.length);
    tmpCerts[signerCertificates_.length] = encryptionCertOfSigner_;
    signerCertificates_ = tmpCerts;
  }
  
  /**
   * Starts the demo.
   *
   *
   * @param argv optional parameters like mailhost, sender name,...
   * 
   * @exception IOException if an I/O related error occurs
   */
  public void start(String[] argv) throws IOException {
    
    int optind = 0;
    if (argv.length > 0) {
      for (optind = 0; optind < argv.length; optind++) {
        if (argv[optind].equals("-H")) {
          host_ = argv[++optind];
        } else if (argv[optind].equals("-S")) {
          senderName_ = argv[++optind];
        } else if (argv[optind].equals("-F")) {
          from_ = argv[++optind];
        } else if (argv[optind].equals("-T")) {
          to_ = argv[++optind];
        } else {
          System.out.println("Usage: SMimeSend [-H host] [-S sender name] [-F (From) sender address] [-T (To) recipient address]");
          System.out.println("e.g.:");
          System.out.println("Usage: SMimeSend -H mailhost -S \"John SMime\" -F smimetest@iaik.tugraz.at -T smimetest@iaik.tugraz.at");
          System.exit(1);
        } 
      }  
    } 


    // get the default Session
  	Session session = DemoSMimeUtil.getSession(host_);

  	try {
      // Create a demo Multipart
      MimeBodyPart mbp1 = new SMimeBodyPart();
	  mbp1.setText("This is a Test of the IAIK S/MIME implementation!\n\n");
      // try to test an attachment
      MimeBodyPart attachment = new SMimeBodyPart();
      attachment.setDataHandler(new DataHandler(new FileDataSource("test.html")));
      attachment.setFileName("test.html");
      Multipart mp = new SMimeMultipart();
      mp.addBodyPart(mbp1);
      mp.addBodyPart(attachment);
      DataHandler multipart = new DataHandler(mp, mp.getContentType());

      Message msg;    // the message to send

      // 1. This is a plain message
      msg = createPlainMessage(session, multipart);
      System.out.println("sending plain message...");
	  Transport.send(msg);

      // 2. This is an explicitly signed message
      msg = createSignedMessage(session, multipart, false);
      System.out.println("sending explicitly signed message...");
	  Transport.send(msg);

      // 3. This is an implicitly signed message
      msg = createSignedMessage(session, multipart, true);
      System.out.println("sending implicitly signed message...");
	  Transport.send(msg);

      // 4. Now create encrypted messages with different content encryption algorithms
      msg = createEncryptedMessage(session, (AlgorithmID)AlgorithmID.rc2_CBC.clone(), 40);
      System.out.println("sending encrypted message [RC2/40]...");
	  Transport.send(msg);
      
      msg = createEncryptedMessage(session, (AlgorithmID)AlgorithmID.rc2_CBC.clone(), 64);
      System.out.println("sending encrypted message [RC2/64]...");
	  Transport.send(msg);
      
      msg = createEncryptedMessage(session, (AlgorithmID)AlgorithmID.rc2_CBC.clone(), 128);
      System.out.println("sending encrypted message [RC2/128]...");
	  Transport.send(msg);
      
      msg = createEncryptedMessage(session, (AlgorithmID)AlgorithmID.des_EDE3_CBC.clone(), 192);
      System.out.println("sending encrypted message [TripleDES]...");
	  Transport.send(msg);

      // 5. Now create a implicitly signed and encrypted message with attachment
      msg = createSignedAndEncryptedMessage(session, multipart, true);
      System.out.println("sending implicitly signed and encrypted message [RC2/40]...");
	  Transport.send(msg);

      // 6. Now create a explicitly signed and encrypted message with attachment
      msg = createSignedAndEncryptedMessage(session, multipart, false);
      System.out.println("sending explicitly signed and encrypted message [RC2/40]...");
	  Transport.send(msg);

	  // 7. certs only message
	  msg = createCertsOnlyMessage(session);
	  System.out.println("sending certs-only message");
	  Transport.send(msg);

	  // 8. second certs only message
	  msg = createCertsOnlyMultiPartMessage(session);
	  System.out.println("sending message with certs-only part");
	  Transport.send(msg);

	  //sending cert request
      msg = createPKCS10Message(session);
      System.out.println("sending application/pkcs10 message...");
	  Transport.send(msg);

	  // ending application/pkcs10 message where the request is in the second part
	  msg = createPKCS10MultiPartMessage(session);
	  System.out.println("sending message with pkcs10 part...");
	  Transport.send(msg);

  	} catch (MessagingException mex) {
      mex.printStackTrace();
	  Exception ex = null;
	  if ((ex = mex.getNextException()) != null) {
        ex.printStackTrace();
	  }
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
    msg.setFrom(new InternetAddress(from_));
	msg.setRecipients(Message.RecipientType.TO,	InternetAddress.parse(to_, false));
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
   * @param dataHandler the content of the message to be signed and encrypted
   * @param implicit whether to use implicit (application/pkcs7-mime) or explicit
   *                 (multipart/signed) signing
   * 
   * @return the signed and encrypted message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createSignedAndEncryptedMessage(Session session, DataHandler dataHandler, boolean implicit)
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
    sc.setCertificates(signerCertificates_);
    try {
      sc.addSigner((RSAPrivateKey)signerPrivateKey_, signerCertificate_, encryptionCertOfSigner_, true);
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Algorithm not supported: " + ex.getMessage(), ex);
    }

    EncryptedContent ec = new EncryptedContent(sc);
    // encrypt for the recipient
    ec.addRecipient(recipientCertificate_, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // I want to be able to decrypt the message, too
    ec.addRecipient(encryptionCertOfSigner_, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
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
   * 
   * @return the signed message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createSignedMessage(Session session, DataHandler dataHandler, boolean implicit)
      throws MessagingException {

    String subject = null;
    StringBuffer buf = new StringBuffer();
    
    if (implicit) {
      subject = "IAIK-S/MIME: Implicitly Signed";
      buf.append("This message is implicitly signed!\n");
      buf.append("You need an S/MIME aware mail client to view this message.\n");
      buf.append("\n\n");
    } else {
      subject = "IAIK-S/MIME: Explicitly Signed";
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
    sc.setCertificates(signerCertificates_);

    try {
      sc.addSigner((RSAPrivateKey)signerPrivateKey_, signerCertificate_, encryptionCertOfSigner_, true);
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
   * @param algorithm the content encryption algorithm to be used
   * @param keyLength the length of the secret content encryption key to be created and used
   * 
   * @return the encrypted message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createEncryptedMessage(Session session, AlgorithmID algorithm, int keyLength)
      throws MessagingException {

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
    // encrypt for the recipient
    ec.addRecipient(recipientCertificate_, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // I want to be able to decrypt the message, too
    ec.addRecipient(encryptionCertOfSigner_, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
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
   * Creates a certs-only message.
   *
   * @param session the mail session
   * 
   * @return the certs-only message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createCertsOnlyMessage(Session session)
      throws MessagingException {

    Message msg = createMessage(session, "IAIK S/MIME: Certs-only message");
    //use new content types
    SMimeParameters.useNewContentTypes(true);
    SignedContent sc = new SignedContent(true, SignedContent.CERTS_ONLY);
    sc.setCertificates(signerCertificates_);
    msg.setContent(sc, sc.getContentType());
    //set filename and attachment parameters
    sc.setHeaders(msg);


    return msg;
  }

  
  /**
   * Creates a certs-only message where the certificate list is transfered as attachment.
   *
   * @param session the mail session
   * 
   * @return the certs-only message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createCertsOnlyMultiPartMessage(Session session) throws MessagingException {

    MimeBodyPart mbp1 = new MimeBodyPart();
	mbp1.setText("This is a test where the certs-only message is included in the second part!\n\n");

    MimeBodyPart attachment = new MimeBodyPart();
    //use new content types
    SMimeParameters.useNewContentTypes(true);
    SignedContent sc = new SignedContent(true, SignedContent.CERTS_ONLY);
    sc.setCertificates(signerCertificates_);
    attachment.setContent(sc, sc.getContentType());
    // let the SignedContent update some message headers
    sc.setHeaders(attachment);
    Multipart mp = new MimeMultipart();
    mp.addBodyPart(mbp1);
    mp.addBodyPart(attachment);

    Message msg = createMessage(session, "IAIK S/MIME: Certs-only multipart message");
    msg.setContent(mp, mp.getContentType());
    return msg;
  }
  
    
  /**
   * Creates a PKCS#10 certificate request message.
   *
   * @param session the mail session
   * 
   * @return the PKCS#10 certificate request message
   *
   * @exception MessagingException if an error occurs when creating the message
   */  
  public Message createPKCS10Message(Session session)
    throws MessagingException {

    Message msg = createMessage(session, "IAIK-S/MIME: Certificate Request");

    PKCS10Content pc = new PKCS10Content();
    CertificateRequest request = null;
    try {
       request = createCertificateRequest();
    } catch (PKCSException ex) {
       throw new MessagingException(ex.getMessage());
    }
    pc.setCertRequest(request);
    msg.setContent(pc, pc.getContentType());
    // let the PKCS10Content update some message headers
    pc.setHeaders(msg);

    return msg;
  }

  /**
   * Creates a PKCS#10 certificate request.
   *
   * @return the certificate request
   *
   * @exception PKCSException if the request cannot be created
   */
  private CertificateRequest createCertificateRequest() throws PKCSException {
    try {
      Name subject = new Name();
	  subject.addRDN(ObjectID.commonName, senderName_);
	  subject.addRDN(ObjectID.emailAddress, from_);
	  CertificateRequest certRequest;

      certRequest = new CertificateRequest(signerCertificate_.getPublicKey(), subject);
  	  certRequest.sign((AlgorithmID)AlgorithmID.sha1WithRSAEncryption.clone(), signerPrivateKey_);
  	  certRequest.verify();
  	  return certRequest;
  	} catch (Exception ex) {
  	  throw new PKCSException("Cannot create cert request: " + ex.getMessage());
  	}

  }
  
  /**
   * Creates a PKCS#10 message where the certificate request is transfered as attachment.
   *
   * @param session the mail session
   * 
   * @return the PKCS#10 certificate request message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createPKCS10MultiPartMessage(Session session) throws MessagingException {

      MimeBodyPart mbp1 = new MimeBodyPart();
	  mbp1.setText("This is a test where the request message is included in the second part!\n\n");
	  // try to test an attachment
	  // this demo attaches our homepage
      MimeBodyPart attachment = new MimeBodyPart();
      //use new content types
      SMimeParameters.useNewContentTypes(true);
      PKCS10Content pc = new PKCS10Content();
      CertificateRequest request = null;
      try {
         request = createCertificateRequest();
      } catch (PKCSException ex) {
         throw new MessagingException(ex.getMessage());
      }
      pc.setCertRequest(request);
      DataHandler pkcs10Handler = new DataHandler(pc, pc.getContentType());
      attachment.setDataHandler(pkcs10Handler);
      attachment.setDisposition("attachment");
      attachment.setFileName("smime.p10");
      Multipart mp = new MimeMultipart();
      mp.addBodyPart(mbp1);
      mp.addBodyPart(attachment);

      Message msg = createMessage(session, "IAIK-S/MIME: Certificate Request multipart message");
      msg.setContent(mp, mp.getContentType());
      return msg;
  }


  /** 
   * Main method.
   */
  public static void main(String[] argv) throws IOException {

    DemoSMimeUtil.initDemos();
   	(new SMimeSendDemo()).start(argv);
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
