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
// $Header: /IAIK-CMS/current/src/demo/smime/basic/BinarySignedDemo.java 15    23.08.13 14:30 Dbratko $
// $Revision: 15 $
//

package demo.smime.basic;

import iaik.smime.BinaryCanonicalizer;
import iaik.smime.DefaultCanonicalizer;
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
 * This class shows how to create, sign and then parse/verify a 
 * mulitpart/signed message where the content is not canonicalized.
 * <p>
 * The only difference to the common usage of this S/MIME library
 * is to use a {@link iaik.smime.BinaryCanonicalizer binary
 * canonicalizer} which does not canonicalize the content.  
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
 * @see iaik.smime.SignedContent
 * @see iaik.smime.BinaryCanonicalizer
 * 
 * @author Dieter Bratko
 */
public class BinarySignedDemo {
    
  // whether to print dump all generates test messages to System.out
  final static boolean PRINT_MESSAGES = false;   

  String firstName_ = "John";                     // name of sender
  String lastName_ = "SMime";
  String from_ = "smimetest@iaik.tugraz.at";      // email sender
  String to_ = "smimetest@iaik.tugraz.at";        // email recipient
  String host_ = "mailhost";                      // name of the mailhost

  X509Certificate[] signerCertificates_;          // list of certificates to include in the S/MIME message
  X509Certificate recipientCertificate_;          // certificate of the recipient
  X509Certificate signerCertificate_;             // certificate of the signer/sender
  X509Certificate encryptionCertOfSigner_;        // signer uses different certificate for encryption
  PrivateKey signerPrivateKey_;                   // private key of the signer/sender
  
  /**
   * Default constructor. Reads certificates and keys from the demo keystore.
   */
  public BinarySignedDemo() {
    
    System.out.println();
    System.out.println("********************************************************************************************");
    System.out.println("*                                 BinarySignedDemo                                         *");
    System.out.println("* (shows how to sign and verify multipart/signed S/MIME messages without canonicalization) *");
    System.out.println("********************************************************************************************");
    System.out.println();
    
    // get the certificates from the KeyStore
    signerCertificates_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    signerPrivateKey_ = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    signerCertificate_ = signerCertificates_[0];

    // recipient = signer for this test
    recipientCertificate_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_)[0];
    PrivateKey recipientKey = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_);
    DumpMessage.privateKey = recipientKey;
    encryptionCertOfSigner_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT)[0];
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
      
      // we use a binary canonicalizer
      SMimeParameters.setCanonicalizer(new BinaryCanonicalizer());
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

     

      // create explicitly signed message
      msg = createSignedMessage(session, multipart);
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
   
  	} catch (Exception ex) {
      ex.printStackTrace();
	  throw new RuntimeException(ex.toString());
  	} finally {
      // reset to default canonicalizer
      SMimeParameters.setCanonicalizer(new DefaultCanonicalizer()); 
    }

  }
  
  /**
   * Creates a signed message.
   *
   * @param session the mail session
   * @param dataHandler the content of the message to be signed
   * 
   * @return the signed message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createSignedMessage(Session session, DataHandler dataHandler)
    throws MessagingException {

    String subject = "IAIK-S/MIME: Explicitly Signed";
    
    MimeMessage msg = new MimeMessage(session);
    msg.setFrom(new InternetAddress(from_));
    msg.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to_, false));
    msg.setSentDate(new Date());
    msg.setSubject(subject);

    SignedContent sc = new SignedContent(false);

    // set content
    sc.setDataHandler(dataHandler);
    sc.setCertificates(signerCertificates_);

    try {
      sc.addSigner((RSAPrivateKey)signerPrivateKey_, signerCertificate_);
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Algorithm not supported: " + ex.getMessage(), ex);
    }

    msg.setContent(sc, sc.getContentType());
    // let the SignedContent update some message headers
    sc.setHeaders(msg);
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
   	(new BinarySignedDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
