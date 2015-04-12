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
// $Header: /IAIK-CMS/current/src/demo/smime/pkcs11/SignedMailDemo.java 8     7.11.13 10:52 Dbratko $
// $Revision: 8 $
//

package demo.smime.pkcs11;

// class and interface imports
import iaik.smime.SMimeBodyPart;
import iaik.smime.SMimeMultipart;
import iaik.smime.SMimeUtil;
import iaik.smime.SignedContent;
import iaik.utils.Util;
import iaik.x509.X509Certificate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;
import java.util.Enumeration;

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
import demo.cms.pkcs11.PKCS11Demo;
import demo.smime.DumpMessage;


/**
 * Base class of signed mail demos using PKCS#11 for accessing
 * the signer key on a smart card. 
 * 
 * @author Dieter Bratko
 */
public abstract class SignedMailDemo extends PKCS11Demo {
  
  // whether to print dump all generates test messages to System.out
  final static boolean PRINT_MESSAGES = true;   
  
  /**
   * Default email address. Used in this demo if signer certificate
   * does not contain an email address.
   */
  private final static String DEFAULT_EMAIL = "smimetest@iaik.tugraz.at";
  
   /**
   * The private key of the signer. In this case only a proxy object, but the
   * application cannot see this.
   */
  protected PrivateKey signerKey_;

  /**
   * The certificate chain of the signer. In contrast to the
   * private signer key, the certificate holds the actual public keying material.
   */
  protected X509Certificate[] signerCertificates_;
  
  /**
   * The email address of the sender.
   */
  protected String sender_;
  
  /**
   * The email address of the recipient.
   */
  protected String recipient_;

  /**
   * Creates a SignedMailDemo object for the given module name.
   * 
   * @param moduleName the name of the module
   * @param userPin the user-pin (password) for the TokenKeyStore
   *                (may be <code>null</code> to pou-up a dialog asking for the pin)
   */
  protected SignedMailDemo(String moduleName, char[] userPin) {
    // install provider in super class    
    super(moduleName, userPin);
  }

  /**
   * This method gets the key stores of all inserted (compatible) smart
   * cards and simply takes the first key-entry. From this key entry it
   * takes the private key and the certificate to retrieve the public key
   * from. The keys are stored in the member variables <code>signerKey_
   * </code> and <code>signerCertificate_</code>.
   *
   * @exception GeneralSecurityException If anything with the provider fails.
   * @exception IOException If loading the key store fails.
   */
  protected void getSignatureKey() throws GeneralSecurityException, IOException
  {
    // we simply take the first keystore, if there are serveral
    Enumeration aliases = tokenKeyStore_.aliases();

    // and we take the first signature (private) key for simplicity
    PrivateKey privateKey = null;
    X509Certificate[] certificates = null;
    while (aliases.hasMoreElements()) {
      String keyAlias = aliases.nextElement().toString();
      Key key = null;
      try {
        key = tokenKeyStore_.getKey(keyAlias, null);
      } catch (NoSuchAlgorithmException ex) {
        throw new GeneralSecurityException(ex.toString());
      }

      if (key instanceof PrivateKey) {
        Certificate[] certificateChain = tokenKeyStore_.getCertificateChain(keyAlias);
        if ((certificateChain != null) && (certificateChain.length > 0)) {
          X509Certificate[] signerCertificates = Util.convertCertificateChain(certificateChain);
          boolean[] keyUsage = signerCertificates[0].getKeyUsage();
          if ((keyUsage == null) || keyUsage[0] || keyUsage[1]) { // check for digital signature or non-repudiation, but also accept if none set
            
            privateKey = (PrivateKey) key;
            certificates = signerCertificates;
            // email address included in certificate?
            String[] emailAddresses = SMimeUtil.getEmailAddresses(certificates[0]);
            if (emailAddresses.length > 0) {
              // in this demo we use same email for sender and recipient
              sender_ = emailAddresses[0];
              recipient_ = emailAddresses[0];
              signerKey_ = privateKey;
              signerCertificates_ = certificates;
              break;
            }
          }
        }  
      }
    }
    
    if (signerKey_ == null) {
      if (privateKey == null) {
        System.out.println("Found no signature key. Ensure that a valid card is inserted and contains a key that is suitable for signing.");
        System.exit(0);
      }   
      signerKey_ = privateKey;
      signerCertificates_ = certificates;
    }
    System.out.println("##########");
    System.out.println("The signer key is: " + signerKey_ );
    System.out.println("##########");
    // get the corresponding certificate for this signer key
    System.out.println("##########");
    System.out.println("The signer certificate is:");
    System.out.println(signerCertificates_[0].toString());
    System.out.println("##########");
    if (sender_ == null) {
      sender_ = DEFAULT_EMAIL;
    }
    if (recipient_ == null) {
      recipient_ = DEFAULT_EMAIL;
    }
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
  protected MimeMessage createSignedMessage(Session session, DataHandler dataHandler, boolean implicit)
    throws MessagingException {

    String subject = null;
    StringBuffer buf = new StringBuffer();
    
    if (implicit) {
      subject = "IAIK-S/MIME Demo: PKCS11 Implicitly Signed";
      buf.append("This message is implicitly signed!\n");
      buf.append("You need an S/MIME aware mail client to view this message.\n");
      buf.append("\n\n");
    } else {
      subject = "IAIK-S/MIME Demo: PKCS11 Explicitly Signed";
      buf.append("This message is explicitly signed!\n");
      buf.append("Every mail client can view this message.\n");
      buf.append("Non S/MIME mail clients will show the signature as attachment.\n");
      buf.append("\n\n");
    }
    
   
    // create SignedContent object
    SignedContent sc = new SignedContent(implicit);

    if (dataHandler != null) {
      sc.setDataHandler(dataHandler);
    } else {
      sc.setText(buf.toString());
    }
    sc.setCertificates(signerCertificates_);

    try {
      sc.addSigner(signerKey_, signerCertificates_[0]);
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Algorithm not supported: " + ex.getMessage(), ex);
    }
    
    // create MimeMessage
    MimeMessage msg = new MimeMessage(session);
    msg.setFrom(new InternetAddress(sender_));
    msg.setRecipients(Message.RecipientType.TO, InternetAddress.parse(recipient_, false));
    msg.setSentDate(new Date());
    msg.setSubject(subject);
    // set signed content
    msg.setContent(sc, sc.getContentType());
    // let the SignedContent update some message headers
    sc.setHeaders(msg);
    return msg;
  }
  
  /**
   * Starts the demo.
   * 
   * @param implicit whether to create an implicit (content included;
   *                 application/pkcs7-mime) or an explicit (content
   *                 not included; multipart/signed) signed message
   *                  
   * @throws Exception if an error occurs
   */
  protected void start(boolean implicit) throws Exception {
    //  Create a demo Multipart
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
    
    // create signed message
    MimeMessage msg = createSignedMessage(DemoSMimeUtil.getSession(), multipart, implicit);
    
    //  we write to a stream
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    msg.saveChanges();
    msg.writeTo(baos); // here you could call Transport.send if you want to send the message
    
    // we read from a stream
    ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
    // parse message
    msg = new MimeMessage(null, bais);
    if (PRINT_MESSAGES) {
      printMessage(msg);
    }
    DumpMessage.dump(msg);
    
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
 
}