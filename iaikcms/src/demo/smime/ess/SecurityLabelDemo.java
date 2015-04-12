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
// $Header: /IAIK-CMS/current/src/demo/smime/ess/SecurityLabelDemo.java 12    23.08.13 14:32 Dbratko $
// $Revision: 12 $
//

package demo.smime.ess;

import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.cms.Utils;
import iaik.smime.SMimeSignerInfo;
import iaik.smime.SignedContent;
import iaik.smime.ess.ESSSecurityLabel;
import iaik.smime.ess.SecurityLabelException;
import iaik.x509.X509Certificate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.util.Date;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import demo.DemoSMimeUtil;
import demo.DemoUtil;
import demo.keystore.CMSKeyStore;

/**
 * Demonstrates the usage of the S/MIME-ESS SecurityLabel attribute.
 * The {@link iaik.smime.ess.ESSSecurityLabel SecurityLabel} attribute may be 
 * included as signed attribute in a {@link iaik.cms.SignerInfo SignerInfo} for
 * providing some kind of "access control" mechanism for the contents of a message.
 * <p> 
 * This demo uses a simple {@link demo.smime.ess.MySecurityLabelHandler 
 * SecurityLabelHandler} that only implements a simple security policy based on
 * the default security classifications "unmarked", "unclassified", "restricted", 
 * "confidential", "secret", "top-secret". Since the SignedData message created
 * by this demo only contains an ESS {@link iaik.smime.ess.ESSSecurityLabel 
 * SecurityLabel} attribute with classification "confidential", only this 
 * classification is processed by the {@link demo.smime.ess.MySecurityLabelHandler 
 * demo handler}. "unmarked" and "unclassified" are handled as "not critical"
 * content (i.e. the content can be accessed by any one), "secret", "top-secret"
 * lock the content (i.e. it is not displayed), and "restricted" and 
 * "confidential" popup a confirmation dialog reminding the recipient about
 * the confidentiality of the message content.
 * 
 * @see demo.smime.ess.MySecurityLabelHandler
 * @see iaik.smime.ess.ESSSecurityLabel
 * 
 * @author Dieter Bratko
 */
public class SecurityLabelDemo {
    
  // whether to print dump all generates test messages to System.out
  final static boolean PRINT_MESSAGES = false;   

  String firstName = "John";
  String lastName = "SMime";
  String to = "smimetest@iaik.at";               // email recipient
  String from = "smimetest@iaik.at";             // email sender
  String host = "mailhost";                      // name of the mailhost

  X509Certificate[] signerCertificates;          // list of certificates to include in the S/MIME message
  X509Certificate signerCertificate;             // certificate of the signer/sender
  PrivateKey signerPrivateKey;                   // private key of the signer/sender
  X509Certificate encryptionCertOfSigner;        // signer uses different certificate for encryption
  
  
  /**
   * Default constructor. Reads certificates and keys from the demo keystore.
   */
  public SecurityLabelDemo() {
    
    System.out.println();
    System.out.println("******************************************************************************************");
    System.out.println("*                               SecurityLabelDemo demo                                   *");
    System.out.println("*                  (shows how to handle the ESS SecurityLabel attribute)                 *");
    System.out.println("******************************************************************************************");
    System.out.println();
    
    // get the certificates from the KeyStore
    signerCertificates = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    signerPrivateKey = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    signerCertificate = signerCertificates[0];
    encryptionCertOfSigner = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT)[0];
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
      Message msg;    // the message to send
      ByteArrayOutputStream baos = new ByteArrayOutputStream(); // we write to a stream
      ByteArrayInputStream bais;  // we read from a stream

      msg = createSignedMessage(session);
      System.out.println("creating implicitly signed message...");
	  baos.reset();
      // send, write
	  msg.saveChanges();
	  msg.writeTo(baos);
      
      // receive, parse
	  bais = new ByteArrayInputStream(baos.toByteArray());
	  msg = new MimeMessage(null, bais);
	  if (PRINT_MESSAGES) {
        printMessage(msg);
      }
	  parseMessage(msg);

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
   * Creates a signed message containing an ESS SecurityLabel attribute.
   *
   * @param session the mail session
   * @return the signed message
   *
   * @exception Exception if an error occurs when creating the message
   */
  public Message createSignedMessage(Session session) throws Exception {

    String subject = "IAIK-S/MIME: SecurityLabelDemo (Explicitly Signed)";
    StringBuffer buf = new StringBuffer();
    buf.append("This is an explicitly signed message\n");
    buf.append("containing an ESSSecurityLabel attribute.\n");
       
    Message msg = createMessage(session, subject);

    SignedContent sc = new SignedContent(true);
    // set the content
    sc.setText(buf.toString());
    
    // set the signer certificates
    sc.setCertificates(signerCertificates);
    // set SignerInfo
    SMimeSignerInfo signerInfo = new SMimeSignerInfo(signerCertificate, 
                                                     (AlgorithmID)AlgorithmID.sha1.clone(),
                                                     (AlgorithmID)AlgorithmID.rsaEncryption.clone(), 
                                                     signerPrivateKey, 
                                                     encryptionCertOfSigner,
                                                     true);
    
    // add SecurityLabel attribute
    ESSSecurityLabel securityLabel = new ESSSecurityLabel(MySecurityLabelHandler.MY_SECURITY_POLICY_ID);
    securityLabel.setSecurityClassification(ESSSecurityLabel.CONFIDENTIAL);
    securityLabel.setPrivacyMarkString("HIGH CONFIDENTIAL DATA MATERIAL! RESTRICTED USER ACCESS");
    signerInfo.addSignedAttribute(new Attribute(securityLabel));
    sc.addSigner(signerInfo);
    msg.setContent(sc, sc.getContentType());
    // let the SignedContent update some message headers
    sc.setHeaders(msg);
    return msg;
  }
  
  /**
   * Parses the signed message, verifies the signature and processes the SecurityLabel
   * attribute.
   * 
   * @param msg the message to be parsed
   * 
   * @throws IOException if an I/O related problem occurs
   * @throws MessagingException if there is a problem with the message format
   * @throws SignatureException if the signature verification failes
   */
  public void parseMessage(Message msg) throws IOException, MessagingException, SignatureException {
    // we know that we have a signed message
    SignedContent sc = (SignedContent)msg.getContent();
    // set a SecurityLabelHandler
    sc.setSecurityLabelHandler(new MySecurityLabelHandler());
    // verify signature
    X509Certificate signer = null;
    try {
      signer = sc.verify();
	  System.out.println("This message is signed from: "+signer.getSubjectDN());
	} catch (SignatureException ex) {
	  throw new SignatureException("Signature verification error: " + ex.toString());
    }
    // try to access the content data
    try {
      Object content = sc.getContent();
      System.out.println("Included content:");
      // depending on JavaMail API version we may have a String or a InputStream
      if (content instanceof String) {
        System.out.println(content);
      } else if (content instanceof InputStream) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Utils.copyStream((InputStream)content, baos, null);
        System.out.println(new String(baos.toByteArray()));
      }  
    } catch (SecurityLabelException ex) {
      System.out.println(ex.getMessage());   
    }    
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
   	try {
   	  (new SecurityLabelDemo()).start();
   	} catch (Exception ex) {
   	  ex.printStackTrace();  
   	}    

    System.out.println("\nReady!");
    DemoUtil.waitKey();
 
  }
}
