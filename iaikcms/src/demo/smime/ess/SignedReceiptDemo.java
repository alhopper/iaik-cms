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
// SUCH DAMAGE.// Copyright (C) 2002 IAIK
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
// $Header: /IAIK-CMS/current/src/demo/smime/ess/SignedReceiptDemo.java 33    23.08.13 14:32 Dbratko $
// $Revision: 33 $
//

package demo.smime.ess;

import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.cms.IssuerAndSerialNumber;
import iaik.cms.SignerInfo;
import iaik.smime.SMimeSignerInfo;
import iaik.smime.SignedContent;
import iaik.smime.ess.ContentIdentifier;
import iaik.smime.ess.ESSException;
import iaik.smime.ess.EntityIdentifier;
import iaik.smime.ess.MLData;
import iaik.smime.ess.MLExpansionHistory;
import iaik.smime.ess.MLReceiptPolicy;
import iaik.smime.ess.Receipt;
import iaik.smime.ess.ReceiptContent;
import iaik.smime.ess.ReceiptRequest;
import iaik.smime.ess.ReceiptsFrom;
import iaik.smime.ess.utils.SenderAndReceiptContentDigest;
import iaik.smime.ess.utils.SignedReceipt;
import iaik.x509.X509Certificate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
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
 * An <a href=http://www.ietf.org/rfc/rfc2634.txt" target="_blank">RFC2634</a> ESS ReceiptRequest -- SignedReceipt demo.
 * <p>
 * This demo creates a message with a {@link iaik.smime.ess.ReceiptRequest
 * ReceiptRequest} attribute and "sends" it to some intended recipient.
 * The recipient then "sends" a signed receipt message back to the
 * original sender who finally validates the signed receipt.
 * A further test run adds a MLA layer with a {@link iaik.smime.ess.MLExpansionHistory
 * MLExpansionHistory} attribute,
 * that supersedes the original receipt request.
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
 * @see iaik.smime.ess.ReceiptRequest 
 * @see iaik.smime.ess.Receipt
 * @see iaik.smime.ess.MLExpansionHistory
 * @see iaik.smime.ess.MLData
 * @see iaik.smime.ess.MLReceiptPolicy
 * @see iaik.smime.ess.utils.SignedReceipt
 * 
 * @author Dieter Bratko
 */
public class SignedReceiptDemo {
    
  // whether to dump all generates test messages to System.out
  final static boolean DUMP_MESSAGES = false;  
 
  // sender (sends a receipt request message)
  String senderName_ = "IAIK Demo Sender";
  // recipient (receives a receipt request and sends a signed receipt)
  String recipientName_ = "IAIK Demo Recipient";
  // an mail list agent
  String mlaName_ = "IAIK Demo ML Agent";
  // we use the same email address for all parties
  String senderAddress_ = "\""+senderName_+"\" <smimetest@iaik.at>";
  String recipientAddress_ = "\""+recipientName_+"\" <smimetest@iaik.at>";
  String mlaAddress_ = "\""+mlaName_+"\" <smimetest@iaik.tugraz.at>";
  
  String host_ = "mailhost";                  // name of the mailhost

  X509Certificate[] signerCertificates_;      // signer certificate list
  X509Certificate signerCertificate_;         // certificate of the signer/sender
  X509Certificate encryptionCertOfSigner_;    // signer uses different certificate for encryption
  PrivateKey signerPrivateKey_;               // private key of the signer/sender
  
  X509Certificate[] recipientCertificates_;   // recipient certificate list
  X509Certificate recipientCertificate_;      // certificate of the recipient
  X509Certificate encryptionCertOfRecipient_; // recipient uses different certificate for encryption
  PrivateKey recipientPrivateKey_;            // private key of the recipient
  
  X509Certificate[] signerCertificatesOfMLA_; // signer certificates of MLA
  PrivateKey signerPrivateKeyOfMLA_;          // signer private key of MLA
 
  
  /**
   * Empty default constructor. Reads all required keys and certificates
   * from the demo keystore (created by running @link demo.keystore.SetupCMSKeySrore)
   * stored at "cms.keystore" in your current working directoy.
   */
  public SignedReceiptDemo() {
    
    System.out.println();
    System.out.println("******************************************************************************************");
    System.out.println("*                               SignedReceiptDemo                                        *");
    System.out.println("*       (shows the usage of the IAIK-CMS library for handling ESS signed receipts)       *");
    System.out.println("******************************************************************************************");
    System.out.println();
    
    // get the certificates from the KeyStore
    signerCertificates_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    signerPrivateKey_ = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    signerCertificate_ = signerCertificates_[0];
    encryptionCertOfSigner_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT)[0];
    recipientCertificates_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_512_SIGN);
    recipientPrivateKey_ = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_512_SIGN);
    recipientCertificate_ = recipientCertificates_[0];
    encryptionCertOfRecipient_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_512_CRYPT)[0];
    signerCertificatesOfMLA_ = CMSKeyStore.getCertificateChain(CMSKeyStore.DSA, CMSKeyStore.SZ_1024_SIGN);
    signerPrivateKeyOfMLA_ = CMSKeyStore.getPrivateKey(CMSKeyStore.DSA, CMSKeyStore.SZ_1024_SIGN);
    X509Certificate[] tmpCerts = new X509Certificate[signerCertificates_.length + 1];
    System.arraycopy(signerCertificates_, 0, tmpCerts, 0, signerCertificates_.length);
    tmpCerts[signerCertificates_.length] = encryptionCertOfSigner_;
    signerCertificates_ = tmpCerts;
    tmpCerts = new X509Certificate[recipientCertificates_.length + 1];
    System.arraycopy(recipientCertificates_, 0, tmpCerts, 0, recipientCertificates_.length);
    tmpCerts[recipientCertificates_.length] = encryptionCertOfRecipient_;
    recipientCertificates_ = tmpCerts;
  }
  
  /**
   * Starts the SignedReceipt demo.
   */
  public void start() {
    boolean implicit = true;
    boolean mla = false;
    System.out.println("Testing receipt request - signed receipt (all implicit)");
    test(implicit, mla);
    mla = true;
    System.out.println("Testing receipt request - MLA - signed receipt (all implicit)");
    test(implicit, mla);
    implicit = false;
    mla = false;
    System.out.println("Testing receipt request - signed receipt (all explicit)");
    test(implicit, mla);
    mla = true;
    System.out.println("Testing receipt request - MLA - signed receipt (all explicit)");
    test(implicit, mla);
    System.out.println("Ready!");
  }
  
  /**
   * Runs the ReceiptRequest - SignedReceipt test.
   *
   * @param implicit whether to create implicit (application/pkcs7-mime) or
   *                 explicit (multipart/signed) ReceiptRequest messages
   * 
   * @param mla whether to add a MLA layer
   */
  public void test(boolean implicit, boolean mla) {

    try {
  	  // get the default Session
  	  Session session = DemoSMimeUtil.getSession();
      
      Message msg;    // the message to send
      ByteArrayOutputStream baos = new ByteArrayOutputStream(); // we write to a stream
      ByteArrayInputStream bais;  // we read from a stream
      
      // we send a signed message with a receipt request
      System.out.println("Creating implicit signed message with receipt request.");
      // create message and "send" it (write it to baos)
      msg = createSignedMessageWithReceiptRequest(session, implicit, baos);
      
      // now parse the receipt request message
	  bais = new ByteArrayInputStream(baos.toByteArray());
	  msg = new MimeMessage(null, bais);
	  if (DUMP_MESSAGES) {
	    dumpMessage(msg);
	  }
	  baos.reset();
	  
	  if (mla == true) {
	    // MLA receives the message and adds a MLExpansionHistory that supersedes the 
	    // original receipt request
	    System.out.println("MLA: parsing received original message.");
	    SignedContent sc = (SignedContent)msg.getContent();
	    System.out.println("MLA: Verifying signature.");
	    // verify the signature (we assume only one signer)
        X509Certificate signer = sc.verify();
	    System.out.println("MLA: This message is signed from: "+signer.getSubjectDN());
	    // add MLExpansionHistory
	    System.out.println("MLA: Creating new signed message with MLExpansionHistory attribute.");
        SignedContent mlaSc = new SignedContent(sc, implicit);
        mlaSc.setCertificates(signerCertificatesOfMLA_);
        try {
          SMimeSignerInfo signerInfo = new SMimeSignerInfo(signerCertificatesOfMLA_[0],
                                                           (AlgorithmID)AlgorithmID.sha1.clone(), 
                                                           (AlgorithmID)AlgorithmID.dsaWithSHA.clone(), 
                                                           signerPrivateKeyOfMLA_);            
          // add a MLExpansionHistory attribute superseding the original receipt request
          MLExpansionHistory mlExpansionHistory = createMLExpansionHistory(signerCertificatesOfMLA_[0],
                                                                           new Date(),
                                                                           mlaAddress_);
          signerInfo.addSignedAttribute(new Attribute(mlExpansionHistory));
          mlaSc.addSigner(signerInfo);
        } catch (NoSuchAlgorithmException ex) {
          throw new MessagingException("Algorithm not supported: " + ex.getMessage(), ex);
        }
        msg = createMessage(session, mlaAddress_, recipientAddress_, "IAIK-S/MIME: MLA with ReceiptRequest");
        msg.setContent(mlaSc, mlaSc.getContentType());
        // let the SignedContent update some message headers
        mlaSc.setHeaders(msg);
        msg.saveChanges();
	    msg.writeTo(baos);
	    
	    // now parse the MLA message
	    bais = new ByteArrayInputStream(baos.toByteArray());
        msg = new MimeMessage(null, bais);
	  
	    if (DUMP_MESSAGES) {
	      dumpMessage(msg);
	    }
      }   
	  
	  // signed receipt creation
	  baos.reset();
	  Message msg1 = createMessageWithSignedReceipt(session, msg);
	  msg1.saveChanges();
	  msg1.writeTo(baos);
	  bais = new ByteArrayInputStream(baos.toByteArray());
	  msg = new MimeMessage(null, bais);

	  if (DUMP_MESSAGES) {
	    dumpMessage(msg);
	  }
	  // signed receipt validation
	  System.out.println("\nNow getting and verifying signed receipt:");
	  verifyReceiptContent(msg);
      
  	} catch (Exception ex) {
	  ex.printStackTrace();
   	  throw new RuntimeException(ex.toString());
  	}

  	
  }
  
  /**
   * Creates a MimeMessage.
   *
   * @param session the current mail session
   * @param from the sender of the message
   * @param to the recipient of the message
   * @param subject the subject of the message
   *
   * @return the newly created MimeMessage
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createMessage(Session session, String from, String to, String subject) throws MessagingException {
    MimeMessage msg = new MimeMessage(session);
    msg.setFrom(new InternetAddress(from));
	msg.setRecipients(Message.RecipientType.TO,	InternetAddress.parse(to, false));
	msg.setSentDate(new Date());
    return msg;
  }

  /**
   * Creates a signed message that contains a <code>ReceiptRequest</code> attribute.
   *
   * @param session the current mail session
   * @param implicit whether to sign the content implicitly or explicitly
   * @param os the output stream to which to write the message
   *
   * @return the message containing a ReceiptRequest attribute
   */
  public Message createSignedMessageWithReceiptRequest(Session session,
                                                       boolean implicit,
                                                       OutputStream os)
    throws Exception {

    Message msg = createMessage(session, senderAddress_, recipientAddress_, "IAIK-S/MIME: ReceiptRequest");
    
    // create the inner signed content
    SignedContent sc = new SignedContent(implicit, implicit ? SignedContent.SIGNED_DATA : null);
    sc.setText("This is a signed message with a ReceiptRequest.");
    
    sc.setCertificates(signerCertificates_);
    SMimeSignerInfo signerInfo = new SMimeSignerInfo(signerCertificate_, 
                                                     (AlgorithmID)AlgorithmID.sha1.clone(),
                                                     (AlgorithmID)AlgorithmID.rsaEncryption.clone(), 
                                                     signerPrivateKey_, 
                                                     encryptionCertOfSigner_,
                                                     true);
    // add a ReceiptRequest attribute to request a receipt to be sent back to the sender
    ReceiptRequest receiptRequest = createReceiptRequest(signerCertificate_.getPublicKey(),
                                                         msg.getSentDate(),
                                                         senderAddress_);
    signerInfo.addSignedAttribute(new Attribute(receiptRequest));
    sc.addSigner(signerInfo);
    msg.setContent(sc, sc.getContentType());
    // let the SignedContent update some message headers
    sc.setHeaders(msg);
    msg.saveChanges();
	msg.writeTo(os);
	// now after sending (writing) the message we can access and keep the digest values for later SignedReceipt validation
    storeDigestValues(sc);
    return msg;
  }
  
  /**
   * Creates a ReceiptRequest attribute to request all recipients to send
   * a signed receipt to the entity to the given email address.
   * 
   * @param publicKey the public key of the sender (used for ContentIdentifier calculation)
   * @param sentDate the sent date of the message (used for ContentIdentifier calculation)
   * @param email the email address of the sender (to whom to return a signed receipt)
   *
   * @return the ReceiptRequest
   */
  public ReceiptRequest createReceiptRequest(PublicKey publicKey, Date sentDate, String email) {
    // we request a receipt from all recipients
    ReceiptsFrom receiptsFrom = new ReceiptsFrom(ReceiptsFrom.ALL_RECIPIENTS);
    // the receipt should be send to the given email
    String[] sendTo = { email };
    // create the signed content identifier
    ContentIdentifier contentIdentifier = new ContentIdentifier(publicKey, sentDate, null);
    // create the receipt request
    ReceiptRequest receiptRequest = new ReceiptRequest(contentIdentifier, receiptsFrom, sendTo);
    return receiptRequest;
  }  
  
  /**
   * Creates a MLExpansionHistory containing only one MLData for
   * the given MLA with given expansion time and a MLReceiptPolicy
   * of type IN_ADDITION_TO for the given mlaEmailAddress.
   *
   * @param mlaCertificate the certificate of the MLA from which to create the
   *        MLData EntityIdentiifier of type IssuerAndSerialNumber
   * @param expansionTime the expansion time
   * @param mlaEmailAddress to be set as IN_ADDITION_TO recipient list for
   *                        the MLData MLRecipientPolicy
   *
   * @return the newly created MLExpansionHistory
   */
  public static MLExpansionHistory createMLExpansionHistory(X509Certificate mlaCertificate,
                                                            Date expansionTime,
                                                            String mlaEmailAddress) {
    
    IssuerAndSerialNumber ias = new IssuerAndSerialNumber(mlaCertificate);
    MLData mlData = new MLData(new EntityIdentifier(ias), expansionTime); 
    MLReceiptPolicy mlReceiptPolicy = new MLReceiptPolicy(MLReceiptPolicy.IN_ADDITION_TO);
    mlReceiptPolicy.setRecipientList(new String[] { mlaEmailAddress });
    mlData.setMLReceiptPolicy(mlReceiptPolicy);
    return new MLExpansionHistory(mlData);
  }  
  
  /**
   * Keeps the signature message digest value of the sender and the receipt content digest
   * values for later SignedReceipt validation.
   *
   * @param signedContent the signed message for which to keep the digest values
   *
   * @exception ESSException if an error occurs while gathering the required digest values
   */
  public void storeDigestValues(SignedContent signedContent) throws ESSException {
    SignerInfo originatorSignerInfo = signedContent.getSignerInfos()[0];
    SenderAndReceiptContentDigest.storeEntry(new SenderAndReceiptContentDigest(originatorSignerInfo));
  }  
  
  /**
   * Creates a signed-receipt message from the received message.
   *
   * @param session the current mail session
   * @param receivedMsg the message containing a ReceiptRequest attribute
   *
   * @return a message containing s signed receipt to be sent in return
   *         to the receipt request
   *
   * @exception Exception if some error occurs during receipt request processing
   *                      or signed receipt creation
   */
  public Message createMessageWithSignedReceipt(Session session, Message receivedMsg) 
          throws Exception {

    SignedReceipt signedReceipt = new SignedReceipt(receivedMsg, recipientAddress_, System.out);
    String subject = "IAIK-S/MIME: Signed Receipt";
         
    Message msg = signedReceipt.createReceiptMessage(recipientPrivateKey_, 
                                                     recipientCertificates_,
                                                     recipientCertificates_[0],
                                                     (AlgorithmID)AlgorithmID.sha1.clone(),
                                                     (AlgorithmID)AlgorithmID.rsaEncryption.clone(),
                                                     encryptionCertOfRecipient_,
                                                     true,
                                                     session,
                                                     subject);
    return msg;
  } 
  
  
  /**
   * Validates a signed receipt message received in return to a receipt request
   * message.
   *
   * @param receiptMsg the message containing the signed receipt
   *
   * @exception if the receipt validation fails for some reason
   */
  public void verifyReceiptContent(Message receiptMsg) throws Exception {
     // we assume to already know of the signed content        
    ReceiptContent receiptContent = (ReceiptContent)receiptMsg.getContent();
    
    Receipt receipt = (Receipt)receiptContent.getContent();
	System.out.println("\nReceipt received:");
	System.out.println(receipt);
	
    
    // verify the signature (we assume only one signer)
    X509Certificate receiptSigner = null;
    try {
      receiptSigner = receiptContent.verify();
	  System.out.println("This receipt content is signed from: "+receiptSigner.getSubjectDN());
	} catch (SignatureException ex) {
	  System.err.println("Signature verification error!");
	  throw ex;
    }
    
  
	try {
	  SenderAndReceiptContentDigest sarcd = SenderAndReceiptContentDigest.validateReceiptContent(receiptContent);
	  // now after validation we may remove the kept digest values from the repository
	  SenderAndReceiptContentDigest.removeEntry(sarcd);
	} catch (ESSException ex) {
	  System.err.println("Signed Receipt validation error!");
	  throw ex;
	}    
	System.out.println("ReceiptContent successful validated!");
  }  
  
  /**
   * Dumps the given message to System.out.
   * 
   * @param msg the message to be dumped
   *
   * @exception Exception if some error occurs
   */
  private static void dumpMessage(Message msg) throws Exception {
    System.out.println("******************************************************************");
    System.out.println("Message dump: \n");
    msg.writeTo(System.out);
    System.out.println("******************************************************************");
  }  
  
  /**
   * Main method.
   */
  public static void main(String[] argv) throws IOException {
    
    try {
      DemoSMimeUtil.initDemos();
   	  (new SignedReceiptDemo()).start();
   	} catch (Exception ex) {
      ex.printStackTrace();   
    }	    

    DemoUtil.waitKey();
   	
  }
}
