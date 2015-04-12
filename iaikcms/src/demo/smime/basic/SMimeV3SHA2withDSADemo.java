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
// $Header: /IAIK-CMS/current/src/demo/smime/basic/SMimeV3SHA2withDSADemo.java 5     23.08.13 14:30 Dbratko $
// $Revision: 5 $
//

package demo.smime.basic;

import iaik.asn1.structures.AlgorithmID;
import iaik.cms.CMSAlgorithmID;
import iaik.smime.SMimeBodyPart;
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
import demo.keystore.CMSKeyStore;
import demo.smime.DumpMessage;

/**
 * This class demonstrates the usage of the IAIK S/MIME implementation with the 
 * SHA2withDSA signature algorithm (FIPS 186-3). It shows how to create signed
 * S/MIMEv3 messages and how to parse them and verify the signature.
 * To run this demo the following packages are required:
 * <ul>
 *    <li>
 *       IAIK-JCE (<code>iaik_jce.jar</code>) version &gt;3.18
 *    </li> 
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
public class SMimeV3SHA2withDSADemo {
  
//whether to print dump all generates test messages to System.out
  final static boolean PRINT_MESSAGES = false;   
  

  String firstName = "John";
  String lastName = "SMime";
  String to = "smimetest@iaik.tugraz.at";     // email recipient
  String from = "smimetest@iaik.tugraz.at";   // email sender
  String host = "mailhost";                       // name of the mailhost

  X509Certificate[] signerCertificates;          // list of certificates to include in the S/MIME message
  X509Certificate signerCertificate;             // certificate of the signer/sender
  PrivateKey signerPrivateKey;                   // private key of the signer/sender
    
  /**
   * Default constructor. Reads certificates and keys from the demo keystore.
   */
  public SMimeV3SHA2withDSADemo() {
    //  get the certificates from the KeyStore
    signerCertificates = CMSKeyStore.getCertificateChain(CMSKeyStore.DSA, CMSKeyStore.SZ_3072_SIGN);
    signerPrivateKey = CMSKeyStore.getPrivateKey(CMSKeyStore.DSA, CMSKeyStore.SZ_3072_SIGN);
    signerCertificate = signerCertificates[0];
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
      
      AlgorithmID digestAlgorithm = CMSAlgorithmID.sha256;
      AlgorithmID signatureAlgorithm = CMSAlgorithmID.dsaWithSHA256;

      //    1. This is an explicitly signed message
      msg = createSignedMessage(session, 
                                multipart, 
                                false,
                                (AlgorithmID)digestAlgorithm.clone(),
                                (AlgorithmID)signatureAlgorithm.clone());
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


      // 2. This is an implicitly signed message
      msg = createSignedMessage(session, 
                                multipart,
                                true, 
                                (AlgorithmID)digestAlgorithm.clone(),
                                (AlgorithmID)signatureAlgorithm.clone());
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

  	} catch (Exception ex) {
      ex.printStackTrace();
	  throw new RuntimeException(ex.toString());
  	}
  }
  
  /**
   * Creates a signed message.
   *
   * @param session the mail session
   * @param dataHandler the content of the message to be signed
   * @param implicit whether to use implicit (application/pkcs7-mime) or explicit
   *                 (multipart/signed) signing
   * @param digestAlgorithm the digest algorithm to be used
   * @param signatureAlgorithm the signature algorithm to be used                
   * 
   * @return the signed message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createSignedMessage(Session session, 
                                     DataHandler dataHandler,
                                     boolean implicit,
                                     AlgorithmID digestAlgorithm,
                                     AlgorithmID signatureAlgorithm)
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
    sc.setCertificates(signerCertificates);

    try {
      sc.addSigner(signerPrivateKey, 
                   signerCertificate,
                   (AlgorithmID)digestAlgorithm.clone(),
                   (AlgorithmID)signatureAlgorithm.clone());
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Algorithm not supported: " + ex.getMessage(), ex);
    }

    msg.setContent(sc, sc.getContentType());
    // let the SignedContent update some message headers
    sc.setHeaders(msg);
    return msg;
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
    msg.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to, false));
    msg.setSentDate(new Date());
    msg.setSubject(subject);
    return msg;
  }
  
  /** 
   * Prints a dump of the given message to System.out.
   *
   * @param msg the message to be dumped to System.out
   *
   * @exception IOException if an I/O error occurs
   */
  static void printMessage(Message msg) throws IOException {
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
    double iaikProviderVersion = DemoUtil.getIaikProviderVersion(); 
    if (iaikProviderVersion <= 3.18) {
      System.err.println("This demo requires a IAIK provider version > 3.18! Your IAIK provider version is " + iaikProviderVersion + ".");
    } else {
      DemoSMimeUtil.initDemos();
   	  (new SMimeV3SHA2withDSADemo()).start();
      System.out.println("\nReady!");
    }  
    DemoUtil.waitKey();
  }
}
