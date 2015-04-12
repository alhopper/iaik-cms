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
// $Header: /IAIK-CMS/current/src/demo/smime/pkcs11/EncryptedMailDemo.java 11    23.08.13 14:33 Dbratko $
// $Revision: 11 $
//

package demo.smime.pkcs11;

// class and interface imports
import iaik.asn1.structures.AlgorithmID;
import iaik.cms.CMSException;
import iaik.smime.EncryptedContent;
import iaik.smime.SMimeBodyPart;
import iaik.smime.SMimeMultipart;
import iaik.smime.SMimeUtil;
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
import demo.DemoUtil;
import demo.cms.pkcs11.PKCS11Demo;
import demo.smime.DumpMessage;



/**
 * This class shows how to en- and decrypt an S/MIME message 
 * using the PKCS#11 provider for accessing the private key
 * on a smart card. This implementation uses the <code>SecurityProvider</code> 
 * feature of the CMS implementation of the IAIK-CMS toolkit.
 * <p>
 * For running this demo the following packages  are required (in addition to 
 * <code>iaik_cms.jar</code> and <code>iaik_cms_demo.jar</code>):
 * <ul>
 *    <li>
 *       <code>iaik_jce(full).jar</code> (IAIK-JCE crypto toolkit)
 *    </li>   
 *    <li>
 *       <code>iaikPkcs11Wrapper.jar</code> (IAIK PKCS#11 Wrapper)
 *    </li>
 *    <li>
 *       <code>iaikPkcs11Provider.jar</code> (IAIK PKCS#11 Provider)
 *    </li>
 *    <li>
 *       The shared PKCS#11 library (<code>pkcs11wrapper.dll</code> for Windows
 *       and <code>libpkcs11wrapper.so</code> for Unix)
 *    </li>
 *    <li>
 *       <code>mail.jar</code>: Get it from <a href="http://www.oracle.com/technetwork/java/javamail/index.html">JavaMail</a>.
 *    </li>   
 *    <li>
 *       <code>activation.jar</code> (required for JDK versions < 1.6): Get it from <a href="http://www.oracle.com/technetwork/java/javase/downloads/index-135046.html">Java Activation Framework</a>.
 *    </li>     
 * </ul>
 * <code>iaik_cms.jar</code>, <code>iaik_cms_demo.jar</code>, <code>iaik_jce(full).jar</code>,
 * <code>iaikPkcs11Wrapper.jar</code> and <code>iaikPkcs11Provider.jar</code> (and
 * <code>mail.jar</code>, <code>activation.jar</code>) have to be put into the classpath, 
 * the shared library (<code>pkcs11wrapper.dll</code> or <code>libpkcs11wrapper.so</code>) 
 * has to be in your system library search path or in your VM library path, e.g. (on Windows,
 * assuming that all jar files in a lib sub-directory and the dll is in a lib/win32 sub-directory,
 * and the module to be used is \"aetpkss1.dll\" (for G&D StarCos and Rainbow iKey 3000)):
 * <pre>
 * java -Djava.library.path=lib/win32 
 *      -cp lib/iaik_jce.jar;lib/iaikPkcs11Wrapper.jar;lib/iaikPkcs11Provider.jar;lib/iaik_cms.jar;lib/iaik_cms_demo.jar;lib/mail.jar;lib/activation.jar
 *      demo.pkcs11.EncryptedMailDemo aetpkss1.dll
 * </pre>
 * You must use JDK 1.2 or later for running this demo.
 * 
 * @author Dieter Bratko
 */
public class EncryptedMailDemo extends PKCS11Demo {
  
  //whether to print dump all generates test messages to System.out
  final static boolean PRINT_MESSAGES = true;   
  
  /**
   * Default email address. Used in this demo if the recipient certificate
   * does not contain an email address.
   */
  private final static String DEFAULT_EMAIL = "smimetest@iaik.tugraz.at";
  

  /**
   * The private key of the recipient. In this case only a proxy object, but the
   * application cannot see this. Used for decryption.
   */
  protected PrivateKey privateKey_;

  /**
   * The certificate of the recipient. In contrast to the private key, the
   * certificate holds holds the actual (public) keying material.
   * Used for encryption.
   */
  protected X509Certificate certificate_;
  
  /**
   * The email address of the sender.
   */
  protected String sender_;
  
  /**
   * The email address of the recipient.
   */
  protected String recipient_;

  /**
   * Creates a EnvelopedDataStreamDemo object for the given module name.
   * 
   * @param moduleName the name of the module
   * @param userPin the user-pin (password) for the TokenKeyStore
   *                (may be <code>null</code> to pou-up a dialog asking for the pin)
   */
  public EncryptedMailDemo(String moduleName, char[] userPin) {
    // install provider in super class
    super(moduleName, userPin);
    System.out.println();
    System.out.println("******************************************************************************Ü*****************************");
    System.out.println("*                                        PKCS#11  ImplicitSignedMailDemo                                   *");
    System.out.println("* (shows how to en/decrypt S/MIME messages using the IAIK-PKCS11 provider for accessing the key on a card) *");
    System.out.println("************************************************************************************************************");
    System.out.println();
  }
  

  /**
   * This method gets the key store of the PKCS#11 provider and searches for a
   * certificate and corresponding private key entry that can en/decrypt the data.
   * Key and cert are stored in the <code>privateKey_</code> and <code>certificate_</code>
   * member variables. Usually you only will have the smartcard on the decryption
   * side (i.e. the sender will get the certificate by other means to use it
   * for encrypting the message), however, for simplicity (and since we do not know
   * which certificate/card you are actually will use for running the demo) we
   * get both, key and certificate from the card.
   *
   * @exception GeneralSecurityException If anything with the provider fails.
   * @exception IOException If loading the key store fails.
   */
  public void getKeyAndCertificate()
      throws GeneralSecurityException, IOException, CMSException
  {
    
    // we simply take the first keystore, if there are serveral
    Enumeration aliases = tokenKeyStore_.aliases();
    
    PrivateKey privateKey = null;
    X509Certificate certificate = null;
    // and we take the first private key for simplicity
    while (aliases.hasMoreElements()) {
      String keyAlias = aliases.nextElement().toString();
      Key key = null;
      try {
        key = tokenKeyStore_.getKey(keyAlias, null);
      } catch (NoSuchAlgorithmException ex) {
        throw new GeneralSecurityException(ex.toString());
      }
      if (key instanceof RSAPrivateKey) {
        Certificate[] certificateChain = tokenKeyStore_.getCertificateChain(keyAlias);
        if ((certificateChain != null) && (certificateChain.length > 0)) {
          X509Certificate[] certificates = Util.convertCertificateChain(certificateChain);
          X509Certificate userCertificate = certificates[0];
          boolean[] keyUsage = userCertificate.getKeyUsage();
          if ((keyUsage == null) || keyUsage[2] || keyUsage[3]) { // check for encryption, but also accept if none set
            // check if there is a receipient info for this certificate
            certificate = userCertificate;
            privateKey = (PrivateKey)key;
            // email address included in recipient certificate?
            String[] emailAddresses = SMimeUtil.getEmailAddresses(certificates[0]);
            if (emailAddresses.length > 0) {
              // in this demo we use same email for sender and recipient
              sender_ = emailAddresses[0];
              recipient_ = emailAddresses[0];
              privateKey_ = privateKey;
              certificate_ = certificate;
              break;
            }
                
          }
        }  
      }
    }

    if (privateKey_ == null) {
      if (privateKey == null) {
        System.out.println("Found no decryption key. Ensure that the correct card is inserted and contains a key that is suitable for decryption.");
        System.exit(0);
      }
      // we did not find a certificate containing an email address
      privateKey_ = privateKey;
      certificate_ = certificate;
      // use default address
      sender_ = DEFAULT_EMAIL;
      recipient_ = DEFAULT_EMAIL;
    }
    System.out.println("##########");
    System.out.println("The decrpytion key is: " + privateKey_);
    System.out.println("##########");
    System.out.println("##########");
    System.out.println("The encryption certificate is:");
    System.out.println(certificate_.toString());
    System.out.println("##########");
  }
  
  
  /**
   * Creates an encrypted message.
   *
   * @param session the mail session
   * @param dataHandler the content of the message to be encrypted
   * 
   * @return the encrypted message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  protected MimeMessage createEncryptedMessage(Session session, DataHandler dataHandler)
    throws MessagingException {

    String subject = "IAIK-S/MIME PKCS11 Demo: Encrypted Mail";
    String text = "This message is encrypted with Triple-DES!\n";
    
   
    // create EncryptedContent object
    EncryptedContent ec = new EncryptedContent();

    if (dataHandler != null) {
      ec.setDataHandler(dataHandler);
    } else {
      ec.setText(text);
    }
 
    ec.addRecipient(certificate_, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    try {
      ec.setEncryptionAlgorithm((AlgorithmID)AlgorithmID.des_EDE3_CBC.clone(), 192);
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Content encryption algorithm not supported: " + ex.getMessage());   
    }   

    
    // create MimeMessage
    MimeMessage msg = new MimeMessage(session);
    msg.setFrom(new InternetAddress(sender_));
    msg.setRecipients(Message.RecipientType.TO, InternetAddress.parse(recipient_, false));
    msg.setSentDate(new Date());
    msg.setSubject(subject);
    // set encrypted content
    msg.setContent(ec, ec.getContentType());
    // let the EncryptedContent update some message headers
    ec.setHeaders(msg);
    return msg;
  }
  
 
  /**
   * Starts the demo.
   */
  public void start() {
    try {
      getKeyStore();
      getKeyAndCertificate();
      // Create a demo contentMultipart
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
      MimeMessage msg = createEncryptedMessage(DemoSMimeUtil.getSession(), multipart);
      
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
      DumpMessage.privateKey = privateKey_;
      DumpMessage.dump(msg);
      System.out.println("##########");
    } catch (Throwable ex) {
      ex.printStackTrace();
      throw new RuntimeException(ex.toString());
    }
  }
  
  /**
   * This is the main method that is called by the JVM during startup.
   *
   * @param args These are the command line arguments.
   */
  public static void main(String[] args) {

    if (args.length == 0) {
      System.out.println("Missing pkcs11 module name.\n");
      printUsage();
    }
    
    String moduleName = args[0];
    char[] userPin = (args.length == 2) ? args[1].toCharArray() : null;
    
    if (args.length > 2) {
      System.out.println("Too many arguments.\n");
      printUsage();
    }
    
    DemoSMimeUtil.initDemos();
    
    (new EncryptedMailDemo(moduleName, userPin)).start();;
    System.out.println("Ready!");
    DemoUtil.waitKey();
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
   * Print usage information.
   */
  private final static void printUsage() {
    System.out.println("Usage:\n");
    System.out.println("java EncryptedMailDemo <pkcs11 module name> [<user-pin>]\n");
    System.out.println("e.g.:");
    System.out.println("java EncryptedMailDemo aetpkss1.dll");
    System.out.println("java EncryptedMailDemo aetpkss1.so");
    DemoUtil.waitKey();
    System.exit(0);
  }




}