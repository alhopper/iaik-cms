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
// $Header: /IAIK-CMS/current/src/demo/smime/ess/TripleWrappingDemo.java 30    23.08.13 14:32 Dbratko $
// $Revision: 30 $
//

package demo.smime.ess;

import iaik.asn1.structures.AlgorithmID;
import iaik.smime.EncryptedContent;
import iaik.smime.SMimeBodyPart;
import iaik.smime.SMimeMultipart;
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
 * An ESS triple wrapping demo. Creates a <a href=http://www.ietf.org/rfc/rfc2634.txt" target="_blank">RFC2634</a> 
 * ESS triple wrapped (signed - encrypted - signed) message and subsequently parses it to 
 * decrypt the layer and verify the signatures.
 * <p>
 * To run this demo the following additional packages are required:
 * <ul>
 *    <li>
 *       <code>mail.jar</code>: Get it from <a href="http://www.oracle.com/technetwork/java/javamail/index.html">JavaMail</a>.
 *    </li>   
 *    <li>
 *       <code>activation.jar</code> (required for JDK versions < 1.6): Get it from <a href="http://www.oracle.com/technetwork/java/javase/downloads/index-135046.html">Java Activation Framework</a>.
 *    </li> 
 * </ul>
 *
 * @see iaik.smime.EncryptedContent
 * @see iaik.smime.SignedContent
 * 
 * @author Dieter Bratko
 */
public class TripleWrappingDemo {
    
  final static boolean DEBUG = false;
   
  // whether to print dump all generates test messages to System.out
  final static boolean PRINT_MESSAGES = false;

  String firstName = "John";
  String lastName = "SMime";
  String to = "smimetest@iaik.at";     // email recipient
  String from = "smimetest@iaik.at";   // email sender
  String host = "mailhost";                       // name of the mailhost

  X509Certificate[] signerCertificates1;          // list of certificates to include in the S/MIME message
  X509Certificate recipientCertificate;          // certificate of the recipient
  X509Certificate signerCertificate1;             // certificate of the signer/sender
  X509Certificate encryptionCertOfSigner1;        // signer uses different certificate for encryption
  PrivateKey signerPrivateKey1;                   // private key of the signer/sender
  
  X509Certificate[] signerCertificates2;          // if outer signer is different than inner signer
  X509Certificate signerCertificate2;             // certificate of the signer/sender
  PrivateKey signerPrivateKey2;                   // private key of the signer/sender
  
  /**
   * Empty default constructor. Reads all required keys and certificates
   * from the demo keystore (created by running @link demo.keystore.SetupCMSKeySrore)
   * stored at "cms.keystore" in your current working directoy.
   */
  public TripleWrappingDemo() {
    
    System.out.println();
    System.out.println("******************************************************************************************");
    System.out.println("*                             TripleWrapping demo                                        *");
    System.out.println("* (shows the usage of the IAIK-CMS library for creating/parsing a triple wrapped message *");
    System.out.println("******************************************************************************************");
    System.out.println();
    
    // get the certificates from the KeyStore
    signerCertificates1 = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    signerPrivateKey1 = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    signerCertificate1 = signerCertificates1[0];

    // recipient = signer for this test
    recipientCertificate = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_)[0];
    PrivateKey recipientKey = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_);
    DumpMessage.privateKey = recipientKey;
    encryptionCertOfSigner1 = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT)[0];
    
    signerCertificates2 = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_512_SIGN);
    signerPrivateKey2 = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_512_SIGN);
    signerCertificate2 = signerCertificates2[0];
  }
  
  /**
   * Starts the demo.
   *
   * @exception if an I/O related error occurs
   */
  public void start() throws IOException {

  	// get the default Session
  	Session session = DemoSMimeUtil.getSession();

  	try {
      // Create a demo Multipart
      MimeBodyPart mbp1 = new SMimeBodyPart();
      mbp1.setText("This is a Test of the IAIK S/MIME implementation!\n\n");
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
  
      // 1. implicitly signed - encrypted - implicitly signed; inner = outer signed
      System.out.println("1. implicitly signed - encrypted - implicitly signed; inner = outer signed");
      msg = tripleWrap(session, multipart, true, true, false);
  	  msg.writeTo(baos);
  	  bais = new ByteArrayInputStream(baos.toByteArray());
  	  msg = new MimeMessage(null, bais);
  	  if (PRINT_MESSAGES) {
  	    printMessage(msg);
  	  }  
  	  DumpMessage.dump(msg);
  	  baos.reset();
  	  System.out.println("\n\n*****************************************\n\n");
	  
	    // 2. implicitly signed - encrypted - implicitly signed; inner != outer signed
      System.out.println("2. implicitly signed - encrypted - implicitly signed; inner != outer signed");
      msg = tripleWrap(session, multipart, true, true, true);
  	  msg.writeTo(baos);
  	  bais = new ByteArrayInputStream(baos.toByteArray());
  	  msg = new MimeMessage(null, bais);
  	  if (PRINT_MESSAGES) {
  	    printMessage(msg);
  	  }  
  	  DumpMessage.dump(msg);
  	  baos.reset();
  	  System.out.println("\n\n*****************************************\n\n");
	  
	    // 3. implicitly signed - encrypted - explicitly signed; inner == outer signed
      System.out.println("3. implicitly signed - encrypted - explicitly signed; inner = outer signed");
      msg = tripleWrap(session, multipart, true, false, false);
  	  msg.writeTo(baos);
  	  bais = new ByteArrayInputStream(baos.toByteArray());
  	  msg = new MimeMessage(null, bais);
  	  if (PRINT_MESSAGES) {
  	    printMessage(msg);
  	  }
  	  DumpMessage.dump(msg);
  	  baos.reset();
  	  System.out.println("\n\n*****************************************\n\n");
  	  
  	  // 4. implicitly signed - encrypted - explicitly signed; inner != outer signed
      System.out.println("4. implicitly signed - encrypted - explicitly signed; inner != outer signed");
      msg = tripleWrap(session, multipart, true, false, true);
  	  msg.writeTo(baos);
  	  bais = new ByteArrayInputStream(baos.toByteArray());
  	  msg = new MimeMessage(null, bais);
  	  if (PRINT_MESSAGES) {
  	    printMessage(msg);
  	  }
  	  DumpMessage.dump(msg);
  	  baos.reset();
  	  System.out.println("\n\n*****************************************\n\n");
  	  
  	  // 5. explicitly signed - encrypted - implicitly signed; inner == outer signed
      System.out.println("5. explicitly signed - encrypted - implicitly signed; inner = outer signed");
      msg = tripleWrap(session, multipart, false, true, false);
  	  msg.writeTo(baos);
  	  bais = new ByteArrayInputStream(baos.toByteArray());
  	  msg = new MimeMessage(null, bais);
  	  if (PRINT_MESSAGES) {
  	    printMessage(msg);
  	  }
  	  DumpMessage.dump(msg);
  	  baos.reset();
  	  System.out.println("\n\n*****************************************\n\n");
  	  
  	  // 6. explicitly signed - encrypted - implicitly signed; inner != outer signed
      System.out.println("6. explicitly signed - encrypted - implicitly signed; inner != outer signed");
      msg = tripleWrap(session, multipart, false, true, true);
  	  msg.writeTo(baos);
  	  bais = new ByteArrayInputStream(baos.toByteArray());
  	  msg = new MimeMessage(null, bais);
  	  if (PRINT_MESSAGES) {
  	    printMessage(msg);
  	  }
  	  DumpMessage.dump(msg);
  	  baos.reset();
  	  System.out.println("\n\n*****************************************\n\n");
  	  
  	  // 7. explicitly signed - encrypted - explicitly signed; inner == outer signed
      System.out.println("7. explicitly signed - encrypted - explicitly signed; inner = outer signed");
      msg = tripleWrap(session, multipart, false, false, false);
  	  msg.writeTo(baos);
  	  bais = new ByteArrayInputStream(baos.toByteArray());
  	  msg = new MimeMessage(null, bais);
  	  if (PRINT_MESSAGES) {
  	    printMessage(msg);
  	  }
  	  DumpMessage.dump(msg);
      baos.reset();
  	  System.out.println("\n\n*****************************************\n\n");
  	  
  	  // 8. explicitly signed - encrypted - explicitly signed; inner != outer signed
      System.out.println("8. explicitly signed - encrypted - explicitly signed; inner != outer signed");
      msg = tripleWrap(session, multipart, false, false, true);
  	  msg.writeTo(baos);
  	  bais = new ByteArrayInputStream(baos.toByteArray());
  	  msg = new MimeMessage(null, bais);
  	  if (PRINT_MESSAGES) {
  	    printMessage(msg);
  	  }
  	  DumpMessage.dump(msg);
  	  baos.reset();
  	  System.out.println("\n\n*****************************************\n\n");
      
      System.out.println("Ready!");
      
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
   * Creates a triple wrapped (signed - encrypted - signed) message.
   *
   * @param session the Session
   * @param dataHandler the data handler providing the raw content
   * @param innerImplicit whether to sign the inner content implicitly or explicitly
   * @param outerImplicit whether to sign the outer content implicitly or explicitly
   * @param differentOuterSigner whether to simulate a different outer signer receiving
   *                             the signed and encrypted message and adding an outer
   *                             layer
   *
   * @return the triple wrapped message
   */
  public Message tripleWrap(Session session, DataHandler dataHandler, 
                            boolean innerImplicit, boolean outerImplicit,
                            boolean differentOuterSigner)
    throws Exception {

    
    StringBuffer buf = new StringBuffer();
    String subject = "IAIK-S/MIME: TripleWrapped:  ";
    buf.append("This is a triple wrapped message where  ");
    if (innerImplicit) {
      subject += "implicit signed - encrypted - "; 
      buf.append("the inner content is implicit signed\n");
    } else {
      subject += "explicit signed - encrypted - "; 
      buf.append("the inner content is explicit signed\n");
    }
    if (outerImplicit) {
      subject += "implicit signed"; 
      buf.append("and the outer content is implicit signed\n");
    } else {
      subject += "explicit signed"; 
      buf.append("and the outer content is explicit signed\n");
    }
    
    Message msg = createMessage(session, subject);
    
    
    // create the inner signed content
    SignedContent sc1 = new SignedContent(innerImplicit);
    if (dataHandler != null) {
      sc1.setDataHandler(dataHandler);
    } else {
      sc1.setText(buf.toString());
    }
    sc1.setCertificates(signerCertificates1);
    try {
      sc1.addSigner((RSAPrivateKey)signerPrivateKey1, signerCertificate1);
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Algorithm not supported: " + ex.getMessage(), ex);
    }
    
    // create the enrypted ("middle") layer
    EncryptedContent ec = new EncryptedContent(sc1);
    ec.setSMimeType();
    // encrypt for the recipient
    ec.addRecipient(recipientCertificate, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // I want to be able to decrypt the message, too
    ec.addRecipient(encryptionCertOfSigner1, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // set the encryption algorithm
    ec.setEncryptionAlgorithm((AlgorithmID)AlgorithmID.des_EDE3_CBC.clone(), 192);
    
    if (differentOuterSigner) {
      // just do a receiving sending step inbetween
      Message msg1 = createMessage(session, "IAIK-S/MIME: Signed and encrypted");
      msg1.setContent(ec, ec.getContentType());
      ec.setHeaders(msg1);
      msg1.saveChanges();
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      msg1.writeTo(baos);
      ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
      msg1 = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg1);
      }  
      // optionally parse message here
	    DumpMessage.dump(msg1);
	    ec = (EncryptedContent)msg1.getContent();
    }    
    
    // create the signed outer layer
    SignedContent sc2 = new SignedContent(ec, outerImplicit);
    
    if (differentOuterSigner) {
      sc2.setCertificates(signerCertificates2);
      try {
        sc2.addSigner((RSAPrivateKey)signerPrivateKey2, signerCertificate2);
      } catch (NoSuchAlgorithmException ex) {
        throw new MessagingException("Algorithm not supported: " + ex.getMessage(), ex);
      }  
    } else {    
      sc2.setCertificates(signerCertificates1);
      try {
        sc2.addSigner((RSAPrivateKey)signerPrivateKey1, signerCertificate1);
      } catch (NoSuchAlgorithmException ex) {
        throw new MessagingException("Algorithm not supported: " + ex.getMessage(), ex);
      }
    }
    msg.setContent(sc2, sc2.getContentType());
    // let the EncryptedContent update some message headers
    sc2.setHeaders(msg);
    msg.saveChanges();
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
   * Main method.
   */
  public static void main(String[] argv) throws IOException {

    DemoSMimeUtil.initDemos();
   	(new TripleWrappingDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
