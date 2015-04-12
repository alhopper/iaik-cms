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
// $Header: /IAIK-CMS/current/src/demo/smime/ess/MLADemo.java 41    23.08.13 14:32 Dbratko $
// $Revision: 41 $
//

package demo.smime.ess;

import iaik.asn1.CodingException;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.asn1.structures.Attributes;
import iaik.cms.CMSSignatureException;
import iaik.cms.IssuerAndSerialNumber;
import iaik.cms.KeyTransRecipientInfo;
import iaik.cms.RecipientInfo;
import iaik.cms.SignerInfo;
import iaik.cms.Utils;
import iaik.smime.EncryptedContent;
import iaik.smime.SMimeBodyPart;
import iaik.smime.SMimeException;
import iaik.smime.SMimeMultipart;
import iaik.smime.SMimeUtil;
import iaik.smime.SignedContent;
import iaik.smime.ess.ESSException;
import iaik.smime.ess.EntityIdentifier;
import iaik.smime.ess.MLData;
import iaik.smime.ess.MLExpansionHistory;
import iaik.smime.ess.MLReceiptPolicy;
import iaik.smime.ess.utils.ESSLayerException;
import iaik.smime.ess.utils.ESSLayers;
import iaik.smime.ess.utils.KeyStoreDatabase;
import iaik.smime.ess.utils.MLA;
import iaik.utils.CryptoUtils;
import iaik.x509.X509Certificate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Date;

import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.activation.FileDataSource;
import javax.mail.BodyPart;
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
import demo.keystore.CMSKeyStoreConstants;

/**
 * A ESS mailing list agent (MLA) demo.
 * Demonstrates the usage of the {@link iaik.smime.ess.utils.MLA MLA} utility by
 * means of the examples given in <a href=http://www.ietf.org/rfc/rfc2634.txt" target="_blank">RFC2634</a>,
 * section 4.2.1:
 * <pre>
 * 4.2.1 Examples of Rule Processing
 *
 * The following examples help explain the rules above:
 *
 * 1) A message (S1(Original Content)) (where S = SignedData) is sent to
 *    the MLA in which the signedData layer does not include an
 *    MLExpansionHistory attribute. The MLA verifies and fully processes
 *    the signedAttributes in S1.  The MLA decides that there is not an
 *    original, received "outer" signedData layer since it finds the
 *    original content, but never finds an envelopedData and never finds
 *    an mlExpansionHistory attribute. The MLA calculates a new
 *    signedData layer, S2, resulting in the following message sent to
 *    the ML recipients: (S2(S1(Original Content))). The MLA includes an
 *    mlExpansionHistory attribute in S2.
 *
 * 2) A message (S3(S2(S1(Original Content)))) is sent to the MLA in
 *    which none of the signedData layers includes an MLExpansionHistory
 *    attribute. The MLA verifies and fully processes the
 *    signedAttributes in S3, S2 and S1. The MLA decides that there is
 *    not an original, received "outer" signedData layer since it finds
 *    the original content, but never finds an envelopedData and never
 *    finds an mlExpansionHistory attribute. The MLA calculates a new
 *    signedData layer, S4, resulting in the following
 *    message sent to the ML recipients:
 *    (S4(S3(S2(S1(Original Content))))). The MLA includes an
 *    mlExpansionHistory attribute in S4.
 *
 * 3) A message (E1(S1(Original Content))) (where E = envelopedData) is
 *    sent to the MLA in which S1 does not include an MLExpansionHistory
 *    attribute.  The MLA decides that there is not an original,
 *    received "outer" signedData layer since it finds the E1 as the
 *    outer layer.  The MLA expands the recipientInformation in E1. The
 *    MLA calculates a new signedData layer, S2, resulting in the
 *    following message sent to the ML recipients:
 *    (S2(E1(S1(Original Content)))). The MLA includes an
 *    mlExpansionHistory attribute in S2.
 *
 * 4) A message (S2(E1(S1(Original Content)))) is sent to the MLA in
 *    which S2 includes an MLExpansionHistory attribute. The MLA verifies
 *    the signature and fully processes the signedAttributes in S2. The
 *    MLA finds the mlExpansionHistory attribute in S2, so it decides
 *    that S2 is the "outer" signedData. The MLA remembers the
 *    signedAttributes included in S2 for later inclusion in the new
 *    outer signedData that it applies to the message. The MLA strips off
 *    S2. The MLA then expands the recipientInformation in E1 (this
 *    invalidates the signature in S2 which is why it was stripped). The
 *    nMLA calculates a new signedData layer, S3, resulting in the
 *    following message sent to the ML recipients: (S3(E1(S1(Original
 *    Content)))). The MLA includes in S3 the attributes from S2 (unless
 *    it specifically replaces an attribute value) including an updated
 *    mlExpansionHistory attribute.
 *
 * 5) A message (S3(S2(E1(S1(Original Content))))) is sent to the MLA in
 *    which none of the signedData layers include an MLExpansionHistory
 *    attribute. The MLA verifies the signature and fully processes the
 *    signedAttributes in S3 and S2. When the MLA encounters E1, then it
 *    decides that S2 is the "outer" signedData since S2 encapsulates E1.
 *    The MLA remembers the signedAttributes included in S2 for later
 *    inclusion in the new outer signedData that it applies to the
 *    message.  The MLA strips off S3 and S2. The MLA then expands the
 *    recipientInformation in E1 (this invalidates the signatures in S3
 *    and S2 which is why they were stripped). The MLA calculates a new
 *    signedData layer, S4, resulting in the following message sent to
 *    the ML recipients: (S4(E1(S1(Original Content)))). The MLA
 *    includes in S4 the attributes from S2 (unless it specifically
 *    replaces an attribute value) and includes a new
 *    mlExpansionHistory attribute.
 *
 * 6) A message (S3(S2(E1(S1(Original Content))))) is sent to the MLA in
 *    which S3 includes an MLExpansionHistory attribute. In this case,
 *    the MLA verifies the signature and fully processes the
 *    signedAttributes in S3. The MLA finds the mlExpansionHistory in S3,
 *    so it decides that S3 is the "outer" signedData. The MLA remembers
 *    the signedAttributes included in S3 for later inclusion in the new
 *    outer signedData that it applies to the message. The MLA keeps on
 *    parsing encapsulated layers because it must determine if there are
 *    any eSSSecurityLabel attributes contained within. The MLA verifies
 *    the signature and fully processes the signedAttributes in S2. When
 *    the MLA encounters E1, then it strips off S3 and S2. The MLA then
 *    expands the recipientInformation in E1 (this invalidates the
 *    signatures in S3 and S2 which is why they were stripped). The MLA
 *    calculates a new signedData layer, S4, resulting in the following
 *    message sent to the ML recipients: (S4(E1(S1(Original Content)))).
 *    The MLA includes in S4 the attributes from S3 (unless it
 *    specifically replaces an attribute value) including an updated
 *    mlExpansionHistory attribute.
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
 * @see iaik.smime.ess.MLExpansionHistory
 * @see iaik.smime.ess.MLData
 * @see iaik.smime.ess.MLReceiptPolicy
 * @see iaik.smime.ess.utils.MLA
 * 
 * @author Dieter Bratko
 */
public class MLADemo {
  // whether to print dump all generates test messages to System.out
  final static boolean DUMP_MESSAGES = false;
  
  // the first party (that sends a message to the MLA)
  String senderName_ = "IAIK Demo Sender";
  // the second party (MLA)
  String mlaName_ = "IAIK Demo ML Agent";
  // the third final party (that receives a message from the MLA)
  String recipientName_ = "IAIK Demo Recipient";
  // we use the same email address for all parties
  String senderAddress_ = "\""+senderName_+"\" <smimetest@iaik.at>";
  String mlaAddress_ = "\""+mlaName_+"\" <smimetest@iaik.at>";
  String recipientAddress_ = "\""+recipientName_+"\" <smimetest@iaik.at>";
  String host_ = "mailhost";                       // name of the mailhost
  
  // required certificate; read from the demo keystore
  X509Certificate[] signerCertificatesOfS1_;            // signer certificates of entity S1
  PrivateKey signerPrivateKeyOfS1_;                     // signer private key of entity S1
  X509Certificate[] signerCertificatesOfS2_;            // signer certificates of entity S2
  PrivateKey signerPrivateKeyOfS2_;                     // signer private key of entity S2
  X509Certificate[] signerCertificatesOfS3_;            // signer certificates of entity S3
  PrivateKey signerPrivateKeyOfS3_;                     // signer private key of entity S3
  X509Certificate[] signerCertificatesOfMLA_;           // signer certificates of MLA
  PrivateKey signerPrivateKeyOfMLA_;                    // signer private key of MLA
  X509Certificate[] encryptionCertificatesOfMLA_;       // encryption certificates of MLA
  PrivateKey encryptionPrivateKeyOfMLA_;                // encryption private key of MLA
  X509Certificate[] certificatesOfMLA_;                 // all (signer + encryption) certificates of the MLA
  X509Certificate[] encryptionCertificatesOfE1_;        // encryption certificates of entity E1
  PrivateKey encryptionPrivateKeyOfE1_;                 // encryption private key of entity E1
  X509Certificate[] recipientCertificates_;             // certificates of the final recipient if the MLA encrypts again
  PrivateKey recipientPrivateKey_;                      // private key of the final recipient if the MLA encrypts again
  
  
  // keystore data base of the MLA
  KeyStoreDatabase keyStoreDatabase_;
  // MLA 
  MLA mla_;
  // MLA id
  EntityIdentifier mlaID_;
  
  /**
   * Empty default constructor. Reads all required keys and certificates
   * from the demo keystore (created by running @link demo.keystore.SetupCMSKeySrore)
   * stored at "cms.keystore" in your current working directoy. Inits the ML agent.
   */ 
  public MLADemo() {
    
    System.out.println();
    System.out.println("******************************************************************************************");
    System.out.println("*                                      MLADemo                                           *");
    System.out.println("*    (shows the usage of the IAIK-CMS MLA utility for running an ESS mail list agent)    *");
    System.out.println("******************************************************************************************");
    System.out.println();
    
    try {
      keyStoreDatabase_ = new KeyStoreDatabase();
      // get the certificates from the KeyStore
      signerCertificatesOfS1_ = CMSKeyStore.getCertificateChain(CMSKeyStore.DSA, CMSKeyStore.SZ_512_SIGN);
      signerPrivateKeyOfS1_ = CMSKeyStore.getPrivateKey(CMSKeyStore.DSA, CMSKeyStore.SZ_512_SIGN);
      signerCertificatesOfS2_ = CMSKeyStore.getCertificateChain(CMSKeyStore.DSA, CMSKeyStore.SZ_1024_SIGN);
      signerPrivateKeyOfS2_ = CMSKeyStore.getPrivateKey(CMSKeyStore.DSA, CMSKeyStore.SZ_1024_SIGN);
      signerCertificatesOfS3_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_512_SIGN);
      signerPrivateKeyOfS3_ = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_512_SIGN);
      signerCertificatesOfMLA_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
      signerPrivateKeyOfMLA_ = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
      encryptionCertificatesOfMLA_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT);
      encryptionPrivateKeyOfMLA_ = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT);
      encryptionCertificatesOfE1_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_512_CRYPT);
      encryptionPrivateKeyOfE1_ = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_512_CRYPT);
      recipientCertificates_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_);
      recipientPrivateKey_ = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_);  
    
      // add the certificates and keys of the MLA to its key data base
      keyStoreDatabase_.addKey(signerPrivateKeyOfMLA_, signerCertificatesOfMLA_, CMSKeyStoreConstants.RSA_1024_SIGN);
      keyStoreDatabase_.addKey(encryptionPrivateKeyOfMLA_, encryptionCertificatesOfMLA_, CMSKeyStoreConstants.RSA_1024_CRYPT);
    
      // init MLA 
      mlaID_ = new EntityIdentifier(new IssuerAndSerialNumber(signerCertificatesOfMLA_[0]));
      mla_ = new MLA(mlaID_);
      mla_.setDebugStream("MLA", System.out);
      // to whom the MLA wants to send an encrypted message
      mla_.setEncryptionInfo(null, 
                             new RecipientInfo[] { new KeyTransRecipientInfo(recipientCertificates_[0], (AlgorithmID)AlgorithmID.rsaEncryption.clone()) },
                             (AlgorithmID)AlgorithmID.des_EDE3_CBC.clone(), 
                             192);
      mla_.setDebugStream("MLA", System.out);
      mla_.setKeyDatabase(keyStoreDatabase_);
      // do not continue to resolve a message if there is an invalid signature in a signed layer
      mla_.setStopOnInvalidSignature(true);                           
      System.out.println("MLA signing cert is: " + signerCertificatesOfMLA_[0].getSubjectDN());
      System.out.println("MLA entity identifier is:\n" + mlaID_ + "\n");
    } catch (Exception ex) {  
      ex.printStackTrace();
   	  throw new RuntimeException(ex.toString());
   	} 
  
  }

  /**
   * Runs the demo samples.
   */
  public void start() {
    
    try {
      
      // get the default Session
  	  Session session = DemoSMimeUtil.getSession();

  	  // Create a demo Multipart
      MimeBodyPart mbp1 = new SMimeBodyPart();
	  mbp1.setText("This is a test of the IAIK-CMS S/MIME ESS MLA implementation.\n");
	  // try to test an attachment
      MimeBodyPart attachment = new SMimeBodyPart();
      attachment.setDataHandler(new DataHandler(new FileDataSource("test.html")));
      attachment.setFileName("test.html");
      Multipart mp = new SMimeMultipart();
      mp.addBodyPart(mbp1);
      mp.addBodyPart(attachment);
    
      // whether to create implcit (content included) or explicit signed messages
      boolean implicit = true;  
      System.out.println("Implicit demos");
      
      // keep original datasource for comparison 
      MimeMessage tmpMsg = new MimeMessage(session);
      tmpMsg.setContent(mp);
      tmpMsg.saveChanges();
      byte[] dsBytes = getDataSource(tmpMsg.getDataHandler());

      System.out.println("Testing sample 4.2.1,1) from RFC 2634: S1(O) ==> S2(S1(O))");
      test_S1_O(session, mp, dsBytes, implicit);  
           
      System.out.println("Testing sample 4.2.1,2) from RFC 2634: S3(S2(S1(O))) ==> S4(S3(S2(S1(O))))");
      test_S3_S2_S1_O(session, mp, dsBytes, implicit);  

      System.out.println("Testing sample 4.2.1,3) from RFC 2634: E1(S1(O)) ==> S2(E1(S1(O)))");
      test_E1_S1_O(session, mp, dsBytes, implicit);  

      System.out.println("Testing sample 4.2.1,4) from RFC 2634: S2(E1(S1(O))) ==> S3(E1(S1(O)))");
      test_S2_E1_S1_O(session, mp, dsBytes, implicit);

      System.out.println("Testing sample 4.2.1,5) from RFC 2634: S3(S2(E1(S1(O)))) ==> S4(E1(S1(O)))");
      test_S3_S2_E1_S1_O(session, mp, dsBytes, implicit, false);

      System.out.println("Testing sample 4.2.1,6) from RFC 2634: S3(S2(E1(S1(O)))) ==> S4(E1(S1(O)))");
      test_S3_S2_E1_S1_O(session, mp, dsBytes, implicit, true);
      
      implicit = false;  
      System.out.println("Explicit demos");
            
      System.out.println("Testing sample 4.2.1,1) from RFC 2634: S1(O) ==> S2(S1(O))");
      test_S1_O(session, mp, dsBytes, implicit);  
           
      System.out.println("Testing sample 4.2.1,2) from RFC 2634: S3(S2(S1(O))) ==> S4(S3(S2(S1(O))))");
      test_S3_S2_S1_O(session, mp, dsBytes, implicit);  

      System.out.println("Testing sample 4.2.1,3) from RFC 2634: E1(S1(O)) ==> S2(E1(S1(O)))");
      test_E1_S1_O(session, mp, dsBytes, implicit);  

      System.out.println("Testing sample 4.2.1,4) from RFC 2634: S2(E1(S1(O))) ==> S3(E1(S1(O)))");
      test_S2_E1_S1_O(session, mp, dsBytes, implicit);

      System.out.println("Testing sample 4.2.1,5) from RFC 2634: S3(S2(E1(S1(O)))) ==> S4(E1(S1(O)))");
      test_S3_S2_E1_S1_O(session, mp, dsBytes, implicit, false);

      System.out.println("Testing sample 4.2.1,6) from RFC 2634: S3(S2(E1(S1(O)))) ==> S4(E1(S1(O)))");
      test_S3_S2_E1_S1_O(session, mp, dsBytes, implicit, true);

      System.out.println("Ready!");
      
    } catch (Exception ex) {  
      ex.printStackTrace();
   	  throw new RuntimeException(ex.toString());
   	}  
  }
    
  /**
   * Tests the MLA behaviour for a simple signed message according to sample 4.2.1,1) of
   * <a href=http://www.ietf.org/rfc/rfc2634.txt" target="_blank">RFC2634</a>:
   * <pre>
   * A message (S1(Original Content)) (where S = SignedData) is sent to
   * the MLA in which the signedData layer does not include an
   * MLExpansionHistory attribute. The MLA verifies and fully processes
   * the signedAttributes in S1.  The MLA decides that there is not an
   * original, received "outer" signedData layer since it finds the
   * original content, but never finds an envelopedData and never finds
   * an mlExpansionHistory attribute. The MLA calculates a new
   * signedData layer, S2, resulting in the following message sent to
   * the ML recipients: (S2(S1(Original Content))). The MLA includes an
   * mlExpansionHistory attribute in S2.
   * </pre>
   * 
   * @param session the current mail session
   * @param mp the multipart content
   * @param dsBytes the original content dataSorce bytes for comparison
   * @param implicit whether implicit (content included) or explicit signing shall be used
   *
   * @exception Exception if an error coours
   */
  public void test_S1_O(Session session, Multipart mp, byte[] dsBytes, boolean implicit) throws Exception {
    //  RFC2634, 4.2.1, 1) S1(Original Content) ==> MLA(S1(Original Content)
    ByteArrayOutputStream baos = new ByteArrayOutputStream(); // we write to a stream
    ByteArrayInputStream bais;  // we read from a stream
    
    // 1. send signed message to MLA
    System.out.println("1. Creating signed message and send it to MLA...");
    Message msg = createMessage(session, senderAddress_, mlaAddress_);
    msg.setSubject("RFC2634, 4.2.1, 1) S1(Original Content)");
    SignedContent sc = create_S1_O(mp, 
                                   mp.getContentType(), 
                                   implicit,
                                   signerCertificatesOfS1_,
                                   signerPrivateKeyOfS1_,
                                   (AlgorithmID)AlgorithmID.sha1.clone(),
                                   (AlgorithmID)AlgorithmID.dsaWithSHA.clone(),
                                   null); 
    msg.setContent(sc, sc.getContentType());                                
    sc.setHeaders(msg);
    msg.saveChanges();
    baos.reset();
    msg.writeTo(baos);
    // 2. MLA: receives messages, processes it and creates and sends a new signed message
    System.out.println("2. MLA: Processing message...");
    bais = new ByteArrayInputStream(baos.toByteArray());
    msg = new MimeMessage(null, bais);
    if (DUMP_MESSAGES) {
      System.out.println("Received message:");  
      dumpMessage(msg);
    }  
    sc = processMessageForMLA(msg, implicit, "S1_O");
    System.out.println("MLA: Sending signed message to new recipient.");
    msg = createMessage(session, mlaAddress_, recipientAddress_);
    msg.setSubject("RFC2634, 4.2.1, 1) MLA(S1(Original Content)");
    msg.setContent(sc, sc.getContentType());
    sc.setHeaders(msg);
    baos.reset();
    msg.writeTo(baos);
    // 3. final recipient: receives message from MLA, parses it and verifies the signature
    System.out.println("3. Final recipient: Parsing message received from MLA...");
    bais = new ByteArrayInputStream(baos.toByteArray());
    msg = new MimeMessage(null, bais);
    if (DUMP_MESSAGES) {
      dumpMessage(msg);
    }    
    // message must be signed by MLA: S2(S1(O)), checking signature S2
    Object content = msg.getContent();
    if ((content instanceof SignedContent == false)) {
      throw new ESSException("Error: received message is not signed!");
    }  
    System.out.println("First layer of message is signed. Verifying signature.");
    DataHandler dh = verify((SignedContent)content, signerCertificatesOfMLA_[0]);
    // read MLExpansionHistory attribute, must contain one MLData entry
    System.out.println("Reading MLExpansionHistory attribute.");
    readMLExpansionHistory((SignedContent)content, 1);
    // second layer must be signed, too
    content = dh.getContent();
    if ((content instanceof SignedContent == false)) {
      throw new ESSException("Error: second layer of received message is not signed!");
    }  
    System.out.println("Second layer of message is signed. Verifying signature.");
    dh = verify((SignedContent)content, signerCertificatesOfS1_[0]);
    // check content
    if (CryptoUtils.equalsBlock(dsBytes, getDataSource(dh)) == false) {
      throw new Exception("Error: Original content changed!"); 
    }  
    dumpContent(dh);
  }  
  
  
  /**
   * Tests the MLA behaviour for a triple signed message according to sample 4.2.1,2) of
   * <a href=http://www.ietf.org/rfc/rfc2634.txt" target="_blank">RFC2634</a>:
   * <pre>
   * A message (S3(S2(S1(Original Content)))) is sent to the MLA in
   * which none of the signedData layers includes an MLExpansionHistory
   * attribute. The MLA verifies and fully processes the
   * signedAttributes in S3, S2 and S1. The MLA decides that there is
   * not an original, received "outer" signedData layer since it finds
   * the original content, but never finds an envelopedData and never
   * finds an mlExpansionHistory attribute. The MLA calculates a new
   * signedData layer, S4, resulting in the following message sent to
   * the ML recipients: (S4(S3(S2(S1(Original Content))))). The MLA 
   * includes an mlExpansionHistory attribute in S4.
   * </pre>
   * 
   * @param session the current mail session
   * @param mp the multipart content
   * @param dsBytes the original content dataSorce bytes for comparison
   * @param implicit whether implicit (content included) or explicit signing shall be used
   *
   * @exception Exception if an error coours
   */
  public void test_S3_S2_S1_O(Session session, Multipart mp, byte[] dsBytes, boolean implicit) throws Exception {
    //  RFC2634, 4.2.1, 2) S3(S2(S1(Original Content))) ==> MLA(S3(S2(S1(Original Content))))
    ByteArrayOutputStream baos = new ByteArrayOutputStream(); // we write to a stream
    ByteArrayInputStream bais;  // we read from a stream
    
    // 1. send signed message to MLA
    System.out.println("1. Creating signed message and send it to MLA...");
    Message msg = createMessage(session, senderAddress_, mlaAddress_);
    msg.setSubject("RFC2634, 4.2.1, 2) S3(S2(S1(Original Content)))");
    SignedContent sc = create_S3_S2_S1_O(mp, 
                                         mp.getContentType(), 
                                         implicit,
                                         signerCertificatesOfS1_,
                                         signerPrivateKeyOfS1_,
                                         (AlgorithmID)AlgorithmID.sha1.clone(),
                                         (AlgorithmID)AlgorithmID.dsaWithSHA.clone(),
                                         null,
                                         implicit,
                                         signerCertificatesOfS2_,
                                         signerPrivateKeyOfS2_,
                                         (AlgorithmID)AlgorithmID.sha1.clone(),
                                         (AlgorithmID)AlgorithmID.dsaWithSHA.clone(),
                                         null,
                                         implicit,
                                         signerCertificatesOfS3_,
                                         signerPrivateKeyOfS3_,
                                         (AlgorithmID)AlgorithmID.sha1.clone(),
                                         (AlgorithmID)AlgorithmID.rsaEncryption.clone(),
                                         null); 
    msg.setContent(sc, sc.getContentType());                                
    sc.setHeaders(msg);
    msg.saveChanges();
    baos.reset();
    msg.writeTo(baos);
    // 2. MLA: receives messages, processes it and creates and sends a new signed message
    System.out.println("2. MLA: Processing message...");
    bais = new ByteArrayInputStream(baos.toByteArray());
    msg = new MimeMessage(null, bais);
    if (DUMP_MESSAGES) {
      System.out.println("Received message:");  
      dumpMessage(msg);
    }  
    sc = processMessageForMLA(msg, implicit, "S3_S2_S1_O");
    System.out.println("MLA: Sending signed message to new recipient.");
    msg = createMessage(session, mlaAddress_, recipientAddress_);
    msg.setSubject("RFC2634, 4.2.1, 2) MLA(S3(S2(S1(Original Content))))");
    msg.setContent(sc, sc.getContentType());
    sc.setHeaders(msg);
    baos.reset();
    msg.writeTo(baos);
    // 3. final recipient: receives message from MLA, parses it and verifies the signature
    System.out.println("3. Final recipient: Parsing message received from MLA...");
    bais = new ByteArrayInputStream(baos.toByteArray());
    msg = new MimeMessage(null, bais);
    if (DUMP_MESSAGES) {
      dumpMessage(msg);
    }    
    // message must be signed by MLA: S4(S3(S2(S1(O)))), checking signature S2
    Object content = msg.getContent();
    if ((content instanceof SignedContent == false)) {
      throw new ESSException("Error: received message is not signed!");
    }  
    System.out.println("First layer of message is signed. Verifying signature.");
    DataHandler dh = verify((SignedContent)content, signerCertificatesOfMLA_[0]);
    // read MLExpansionHistory attribute, must contain one MLData entry
    System.out.println("Reading MLExpansionHistory attribute.");
    readMLExpansionHistory((SignedContent)content, 1);
    // second layer must be signed, too
    content = dh.getContent();
    if ((content instanceof SignedContent == false)) {
      throw new ESSException("Error: second layer of received message is not signed!");
    }  
    System.out.println("Second layer of message is signed. Verifying signature.");
    dh = verify((SignedContent)content, signerCertificatesOfS3_[0]);
    // third layer must be signed, too
    content = dh.getContent();
    if ((content instanceof SignedContent == false)) {
      throw new ESSException("Error: third layer of received message is not signed!");
    }  
    System.out.println("Third layer of message is signed. Verifying signature.");
    dh = verify((SignedContent)content, signerCertificatesOfS2_[0]);
    // fourth layer must be signed, too
    content = dh.getContent();
    if ((content instanceof SignedContent == false)) {
      throw new ESSException("Error: fourth layer of received message is not signed!");
    }  
    System.out.println("Fourth layer of message is signed. Verifying signature.");
    dh = verify((SignedContent)content, signerCertificatesOfS1_[0]);
    // check content
    if (CryptoUtils.equalsBlock(dsBytes, getDataSource(dh)) == false) {
      throw new Exception("Error: Original content changed!"); 
    }  
    dumpContent(dh);
  }
  
  /**
   * Tests the MLA behaviour for a encrypted and signed signed message according to 
   * sample 4.2.1,3) of <a href=http://www.ietf.org/rfc/rfc2634.txt" target="_blank">RFC2634</a>:
   * <pre>
   * A message (E1(S1(Original Content))) (where E = envelopedData) is
   * sent to the MLA in which S1 does not include an MLExpansionHistory
   * attribute.  The MLA decides that there is not an original,
   * received "outer" signedData layer since it finds the E1 as the
   * outer layer.  The MLA expands the recipientInformation in E1. The
   * MLA calculates a new signedData layer, S2, resulting in the
   * following message sent to the ML recipients:
   * (S2(E1(S1(Original Content)))). The MLA includes an
   * mlExpansionHistory attribute in S2.
   * </pre>
   * 
   * @param session the current mail session
   * @param mp the multipart content
   * @param dsBytes the original content dataSorce bytes for comparison
   * @param implicit whether implicit (content included) or explicit signing shall be used
   *
   * @exception Exception if an error coours
   */
  public void test_E1_S1_O(Session session, Multipart mp, byte[] dsBytes, boolean implicit) throws Exception {
    //  RFC2634, 4.2.1, 3) E1(S1(Original Content)) ==> MLA(E1(S1(Original Content)))
    ByteArrayOutputStream baos = new ByteArrayOutputStream(); // we write to a stream
    ByteArrayInputStream bais;  // we read from a stream
    
    // 1. send signed and encrypted message to MLA
    System.out.println("1. Creating signed and encrypted message and send it to MLA...");
    Message msg = createMessage(session, senderAddress_, mlaAddress_);
    msg.setSubject("RFC2634, 4.2.1, 3) E1(S1(Original Content))");
    EncryptedContent ec = create_E1_S1_O(mp, 
                                      mp.getContentType(), 
                                      implicit,
                                      signerCertificatesOfS1_,
                                      signerPrivateKeyOfS1_,
                                      (AlgorithmID)AlgorithmID.sha1.clone(),
                                      (AlgorithmID)AlgorithmID.dsaWithSHA.clone(),
                                      null,
                                      encryptionCertificatesOfMLA_[0],
                                      (AlgorithmID)AlgorithmID.rsaEncryption,
                                      (AlgorithmID)AlgorithmID.des_EDE3_CBC.clone(),
                                       192); 
    msg.setContent(ec, ec.getContentType());                                
    ec.setHeaders(msg);
    msg.saveChanges();
    baos.reset();
    msg.writeTo(baos);
    // 2. MLA: receives messages, processes it and creates and sends a new signed message
    System.out.println("2. MLA: Processing message...");
    bais = new ByteArrayInputStream(baos.toByteArray());
    msg = new MimeMessage(null, bais);
    if (DUMP_MESSAGES) {
      System.out.println("Received message:");  
      dumpMessage(msg);
    }  
    SignedContent sc = processMessageForMLA(msg, implicit, "E1_S1_O");
    System.out.println("MLA: Sending signed message to new recipient.");
    msg = createMessage(session, mlaAddress_, recipientAddress_);
    msg.setSubject("RFC2634, 4.2.1, 3) MLA(E1(S1(Original Content)))");
    msg.setContent(sc, sc.getContentType());
    sc.setHeaders(msg);
    baos.reset();
    msg.writeTo(baos);
    // 3. final recipient: receives message from MLA, parses it
    System.out.println("3. Final recipient: Parsing message received from MLA...");
    bais = new ByteArrayInputStream(baos.toByteArray());
    msg = new MimeMessage(null, bais);
    if (DUMP_MESSAGES) {
      dumpMessage(msg);
    }    
    // message must be signed by MLA: S2(E1(S1(O))), checking signature S2
    Object content = msg.getContent();
    if ((content instanceof SignedContent == false)) {
      throw new ESSException("Error: received message is not signed!");
    }  
    System.out.println("First layer of message is signed. Verifying signature.");
    DataHandler dh = verify((SignedContent)content, signerCertificatesOfMLA_[0]);
    // read MLExpansionHistory attribute, must contain one MLData entry
    System.out.println("Reading MLExpansionHistory attribute.");
    readMLExpansionHistory((SignedContent)content, 1);
    // second layer must be encrypted
    content = dh.getContent();
    if ((content instanceof EncryptedContent == false)) {
      throw new ESSException("Error: second layer of received message is not encrypted!");
    }  
    System.out.println("Second layer of message is encrypted. Trying to decrypt.");
    dh = decrypt((EncryptedContent)content, recipientPrivateKey_, recipientCertificates_[0]);
    // third layer must be signed, too
    content = dh.getContent();
    if ((content instanceof SignedContent == false)) {
      throw new ESSException("Error: second layer of received message is not signed!");
    }  
    System.out.println("Third layer of message is signed. Verifying signature.");
    dh = verify((SignedContent)content, signerCertificatesOfS1_[0]);
    // check content
    if (CryptoUtils.equalsBlock(dsBytes, getDataSource(dh)) == false) {
      throw new Exception("Error: Original content changed!"); 
    }  
    dumpContent(dh);
  }
  
  /**
   * Tests the MLA behaviour for signed encrypted and signed signed message according to 
   * sample 4.2.1,4) of <a href=http://www.ietf.org/rfc/rfc2634.txt" target="_blank">RFC2634</a>:
   * <pre>
   * A message (S2(E1(S1(Original Content)))) is sent to the MLA in
   * which S2 includes an MLExpansionHistory attribute. The MLA verifies
   * the signature and fully processes the signedAttributes in S2. The
   * MLA finds the mlExpansionHistory attribute in S2, so it decides
   * that S2 is the "outer" signedData. The MLA remembers the
   * signedAttributes included in S2 for later inclusion in the new
   * outer signedData that it applies to the message. The MLA strips off
   * S2. The MLA then expands the recipientInformation in E1 (this
   * invalidates the signature in S2 which is why it was stripped). The
   * nMLA calculates a new signedData layer, S3, resulting in the
   * following message sent to the ML recipients: (S3(E1(S1(Original
   * Content)))). The MLA includes in S3 the attributes from S2 (unless
   * it specifically replaces an attribute value) including an updated
   * mlExpansionHistory attribute.
   * </pre>
   * 
   * @param session the current mail session
   * @param mp the multipart content
   * @param dsBytes the original content dataSorce bytes for comparison
   * @param implicit whether implicit (content included) or explicit signing shall be used
   *
   * @exception Exception if an error coours
   */
  public void test_S2_E1_S1_O(Session session, Multipart mp, byte[] dsBytes, boolean implicit) throws Exception {
    //  RFC2634, 4.2.1, 4) S2(E1(S1(Original Content))) ==> MLA(E1(S1(Original Content)))
    ByteArrayOutputStream baos = new ByteArrayOutputStream(); // we write to a stream
    ByteArrayInputStream bais;  // we read from a stream
    
    // 1. send signed and encrypted and signed message to MLA
    System.out.println("1. Creating signed and encrypted/signed message and send it to MLA...");
    Message msg = createMessage(session, senderAddress_, mlaAddress_);
    msg.setSubject("RFC2634, 4.2.1, 4) S2(E1(S1(Original Content)))");
    SignedContent sc = create_S2_E1_S1_0(mp, 
                                         mp.getContentType(), 
                                         implicit,
                                         signerCertificatesOfS1_,
                                         signerPrivateKeyOfS1_,
                                         (AlgorithmID)AlgorithmID.sha1.clone(),
                                         (AlgorithmID)AlgorithmID.dsaWithSHA.clone(),
                                         null,
                                         encryptionCertificatesOfMLA_[0],
                                         (AlgorithmID)AlgorithmID.rsaEncryption.clone(),
                                         (AlgorithmID)AlgorithmID.des_EDE3_CBC.clone(),
                                         192,
                                         implicit,
                                         signerCertificatesOfS2_,
                                         signerPrivateKeyOfS2_,
                                         (AlgorithmID)AlgorithmID.sha1.clone(),
                                         (AlgorithmID)AlgorithmID.dsaWithSHA1.clone(),
                                         createMLExpansionHistory(signerCertificatesOfS2_[0], new Date(), null)); 
    msg.setContent(sc, sc.getContentType());                                
    sc.setHeaders(msg);
    msg.saveChanges();
    baos.reset();
    msg.writeTo(baos);
    // 2. MLA: receives messages, processes it and creates and sends a new signed message
    System.out.println("2. MLA: Processing message...");
    bais = new ByteArrayInputStream(baos.toByteArray());
    msg = new MimeMessage(null, bais);
    if (DUMP_MESSAGES) {
      System.out.println("Received message:");  
      dumpMessage(msg);
    }  
    sc = processMessageForMLA(msg, implicit, "S2_E1_S1_0");
    System.out.println("MLA: Sending signed message to new recipient.");
    msg = createMessage(session, mlaAddress_, recipientAddress_);
    msg.setSubject("RFC2634, 4.2.1, 4) MLA(E1(S1(Original Content)))");
    msg.setContent(sc, sc.getContentType());
    sc.setHeaders(msg);
    baos.reset();
    msg.writeTo(baos);
    // 3. final recipient: receives message from MLA, parses it
    System.out.println("3. Final recipient: Parsing message received from MLA...");
    bais = new ByteArrayInputStream(baos.toByteArray());
    msg = new MimeMessage(null, bais);
    if (DUMP_MESSAGES) {
      dumpMessage(msg);
    }    
    // message must be signed by MLA: S3(E1(S1(O))), checking signature S3
    Object content = msg.getContent();
    if ((content instanceof SignedContent == false)) {
      throw new ESSException("Error: received message is not signed!");
    }  
    System.out.println("First layer of message is signed. Verifying signature.");
    DataHandler dh = verify((SignedContent)content, signerCertificatesOfMLA_[0]);
    // read MLExpansionHistory attribute, must contain one MLData entry
    System.out.println("Reading MLExpansionHistory attributes.");
    readMLExpansionHistory((SignedContent)content, 2);
    // second layer must be encrypted
    content = dh.getContent();
    if ((content instanceof EncryptedContent == false)) {
      throw new ESSException("Error: second layer of received message is not encrypted!");
    }  
    System.out.println("Second layer of message is encrypted. Trying to decrypt.");
    dh = decrypt((EncryptedContent)content, recipientPrivateKey_, recipientCertificates_[0]);
    // third layer must be signed, too
    content = dh.getContent();
    if ((content instanceof SignedContent == false)) {
      throw new ESSException("Error: second layer of received message is not signed!");
    }  
    System.out.println("Third layer of message is signed. Verifying signature.");
    dh = verify((SignedContent)content, signerCertificatesOfS1_[0]);
    // check content
    if (CryptoUtils.equalsBlock(dsBytes, getDataSource(dh)) == false) {
      throw new Exception("Error: Original content changed!"); 
    }  
    dumpContent(dh);
  }
  
  /**
   * Tests the MLA behaviour for double signed encrypted and signed signed message 
   * according to  sample 4.2.1,5) of <a href=http://www.ietf.org/rfc/rfc2634.txt" target="_blank">RFC2634</a>:
   * <pre>
   * A message (S3(S2(E1(S1(Original Content))))) is sent to the MLA in
   * which none of the signedData layers include an MLExpansionHistory
   * attribute. The MLA verifies the signature and fully processes the
   * signedAttributes in S3 and S2. When the MLA encounters E1, then it
   * decides that S2 is the "outer" signedData since S2 encapsulates E1.
   * The MLA remembers the signedAttributes included in S2 for later
   * inclusion in the new outer signedData that it applies to the
   * message.  The MLA strips off S3 and S2. The MLA then expands the
   * recipientInformation in E1 (this invalidates the signatures in S3
   * and S2 which is why they were stripped). The MLA calculates a new
   * signedData layer, S4, resulting in the following message sent to
   * the ML recipients: (S4(E1(S1(Original Content)))). The MLA
   * includes in S4 the attributes from S2 (unless it specifically
   * replaces an attribute value) and includes a new
   * mlExpansionHistory attribute.
   * </pre>
   * 
   * @param session the current mail session
   * @param mp the multipart content
   * @param dsBytes the original content dataSorce bytes for comparison
   * @param implicit whether implicit (content included) or explicit signing shall be used
   * @param includeMLExpansionHistoryInS3 whether to include an MLExpansionHistory in the
   *                                      the outermost signed layer (S3) of the original
   *                                      message
   *
   * @exception Exception if an error coours
   */
  public void test_S3_S2_E1_S1_O(Session session, 
                                 Multipart mp, 
                                 byte[] dsBytes, 
                                 boolean implicit,
                                 boolean includeMLExpansionHistoryInS3) throws Exception {
    //  RFC2634, 4.2.1, 5) S3(S2(E1(S1(Original Content)))) ==> MLA(E1(S1(Original Content)))
    ByteArrayOutputStream baos = new ByteArrayOutputStream(); // we write to a stream
    ByteArrayInputStream bais;  // we read from a stream
    
    // 1. send double signed and encrypted and signed message to MLA
    System.out.println("1. Creating double signed and encrypted/signed message and send it to MLA...");
    Message msg = createMessage(session, senderAddress_, mlaAddress_);
    msg.setSubject("RFC2634, 4.2.1, 5) S3(S2(E1(S1(Original Content))))");
    SignedContent sc = create_S3_S2_E1_S1_0(mp, 
                                            mp.getContentType(), 
                                            implicit,
                                            signerCertificatesOfS1_,
                                            signerPrivateKeyOfS1_,
                                            (AlgorithmID)AlgorithmID.sha1.clone(),
                                            (AlgorithmID)AlgorithmID.dsaWithSHA.clone(),
                                            null,
                                            encryptionCertificatesOfMLA_[0],
                                            (AlgorithmID)AlgorithmID.rsaEncryption.clone(),
                                            (AlgorithmID)AlgorithmID.des_EDE3_CBC.clone(),
                                            192,
                                            implicit,
                                            signerCertificatesOfS2_,
                                            signerPrivateKeyOfS2_,
                                            (AlgorithmID)AlgorithmID.sha1.clone(),
                                            (AlgorithmID)AlgorithmID.dsaWithSHA.clone(),
                                            null,
                                            implicit,
                                            signerCertificatesOfS3_,
                                            signerPrivateKeyOfS3_,
                                            (AlgorithmID)AlgorithmID.sha1.clone(),
                                            (AlgorithmID)AlgorithmID.rsaEncryption.clone(),
                                            (includeMLExpansionHistoryInS3 ?
                                            createMLExpansionHistory(signerCertificatesOfS3_[0], new Date(), null) :
                                            null));
    msg.setContent(sc, sc.getContentType());                                
    sc.setHeaders(msg);
    msg.saveChanges();
    baos.reset();
    msg.writeTo(baos);
    // 2. MLA: receives messages, processes it and creates and sends a new signed message
    System.out.println("2. MLA: Processing message...");
    bais = new ByteArrayInputStream(baos.toByteArray());
    msg = new MimeMessage(null, bais);
    if (DUMP_MESSAGES) {
      System.out.println("Received message:");  
      dumpMessage(msg);
    }  
    sc = processMessageForMLA(msg, implicit, "S3_S2_E1_S1_0");
    System.out.println("MLA: Sending signed message to new recipient.");
    msg = createMessage(session, mlaAddress_, recipientAddress_);
    msg.setSubject("RFC2634, 4.2.1, 5) MLA(E1(S1(Original Content)))");
    msg.setContent(sc, sc.getContentType());
    sc.setHeaders(msg);
    baos.reset();
    msg.writeTo(baos);
    // 3. final recipient: receives message from MLA, parses it
    System.out.println("3. Final recipient: Parsing message received from MLA...");
    bais = new ByteArrayInputStream(baos.toByteArray());
    msg = new MimeMessage(null, bais);
    if (DUMP_MESSAGES) {
      dumpMessage(msg);
    }    
    // message must be signed by MLA: S4(E1(S1(O))), checking signature S4
    Object content = msg.getContent();
    if ((content instanceof SignedContent == false)) {
      throw new ESSException("Error: received message is not signed!");
    }  
    System.out.println("First layer of message is signed. Verifying signature.");
    DataHandler dh = verify((SignedContent)content, signerCertificatesOfMLA_[0]);
    // read MLExpansionHistory attribute, must contain one MLData entry
    System.out.println("Reading MLExpansionHistory attributes.");
    readMLExpansionHistory((SignedContent)content, includeMLExpansionHistoryInS3 ? 2 : 1);
    // second layer must be encrypted
    content = dh.getContent();
    if ((content instanceof EncryptedContent == false)) {
      throw new ESSException("Error: second layer of received message is not encrypted!");
    }  
    System.out.println("Second layer of message is encrypted. Trying to decrypt.");
    dh = decrypt((EncryptedContent)content, recipientPrivateKey_, recipientCertificates_[0]);
    // third layer must be signed, too
    content = dh.getContent();
    if ((content instanceof SignedContent == false)) {
      throw new ESSException("Error: second layer of received message is not signed!");
    }  
    System.out.println("Third layer of message is signed. Verifying signature.");
    dh = verify((SignedContent)content, signerCertificatesOfS1_[0]);
    // check content
    if (CryptoUtils.equalsBlock(dsBytes, getDataSource(dh)) == false) {
      throw new Exception("Error: Original content changed!"); 
    }  
    dumpContent(dh);
  }

  /**
   * Creates a new MimeMessage without content and sets the From:, To:, and Date: headers.
   * 
   * @param session the current mail session
   * @param from the address of the sender of the message
   * @param to the address of the indented message recipient
   * @return the new created MimeMessage
   * @exception MessagingException if an error occurs when setting the message headers
   */
  public Message createMessage(Session session, String from, String to) throws MessagingException {
    MimeMessage msg = new MimeMessage(session);
    msg.setFrom(new InternetAddress(from));
	msg.setRecipients(Message.RecipientType.TO,	InternetAddress.parse(to, false));
	msg.setSentDate(new Date());
    return msg;
  }
  
  /**
   * Creates a SignedContent.
   *
   * @param content the content to be signed
   * @param contentType the MIME type of the content
   * @param implicit whether to create an implicit (application/pkcs7-mime) or 
   *                 explicit (multipart/signed) message
   * @param signerCertificates the certificate chain of the signer
   * @param signerPrivateKey the private key to be used for signing the content
   * @param digestAlg the algorithm to be used for digest calculation
   * @param signatureAlg the algorithm to be used for signature calculation
   * @param mlExpansionHistory MLExpansionHistory attribute to be added; maybe null
   *
   * @return the SignedContent
   *
   * @exception MessagingException if a problem occurs when creating the SignedContent
   */
  public SignedContent createSignedContent(Object content, 
                                           String contentType, 
                                           boolean implicit,
                                           X509Certificate[] signerCertificates,
                                           PrivateKey signerPrivateKey,
                                           AlgorithmID digestAlg,
                                           AlgorithmID signatureAlg,
                                           MLExpansionHistory mlExpansionHistory)
    throws MessagingException {

    SignedContent sc = new SignedContent(implicit);
    sc.setContent(content, contentType);
    sc.setCertificates(signerCertificates);
    try {
      // create a set of standard attributes
      Attributes attributes = SMimeUtil.makeStandardAttributes();
      if (mlExpansionHistory != null) {
        attributes.addAttribute(new Attribute(mlExpansionHistory));
      }
      sc.addSigner(signerPrivateKey, signerCertificates[0], digestAlg, signatureAlg, attributes.toArray());
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Algorithm not supported: " + ex.getMessage(), ex);
    } catch (CodingException ex) {
      throw new MessagingException("Error in attribute encoding: " + ex.getMessage());   
    } catch (SMimeException ex) {
      throw new MessagingException("Error adding attributes: " + ex.toString());   
    }    

    return sc;
  }
  
  /**
   * Creates an EncryptedContent.
   *
   * @param content the content to be encrypted
   * @param contentType the MIME type of the content
   * @param recipientCertificate the encryption certificate of the recipient
   * @param cekEncrAlg the algorithm to be used for encrypting the symmetric content encryption key
   *                   (e.g. AlgorithmID.rsaEncryption)
   * @param contentEncrAlg the symmetric key to be used for encrypting the content, e.g. AlgorithmID.des_EDE3_CBC
   * @param cekLength the length of the temporary content encryption key to be generated (e.g. 192)
   *
   * @return the EncryptedContent
   *
   * @exception MessagingException if a problem occurs when creating the EncryptedContent
   */
  public EncryptedContent createEncryptedContent(Object content, 
                                                 String contentType,
                                                 X509Certificate recipientCertificate,
                                                 AlgorithmID cekEncrAlg,
                                                 AlgorithmID contentEncrAlg,
                                                 int cekLength) throws MessagingException {

    EncryptedContent ec = new EncryptedContent();
    ec.setContent(content, contentType);
    // encrypt for the recipient
    ec.addRecipient(recipientCertificate, cekEncrAlg);
    try {
      ec.setEncryptionAlgorithm(contentEncrAlg, cekLength);
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Content encryption algorithm not supported: " + ex.getMessage());   
    }   

    return ec;
  }
  
  /**
   * Signs the given content.
   *
   * @param content the content to be signed
   * @param contentType the MIME type of the content
   * @param implicitS1 whether to create an implicit (application/pkcs7-mime) or 
   *                 explicit (multipart/signed) message
   * @param signerCertificatesS1 the certificate chain of the signer
   * @param signerPrivateKeyS1 the private key to be used for signing the content
   * @param digestAlgS1 the algorithm to be used for digest calculation
   * @param signatureAlgS1 the algorithm to be used for signature calculation
   * @param mlExpansionHistoryS1 MLExpansionHistory attribute to be added; maybe null
   *
   * @return the SignedContent
   *
   * @exception MessagingException if a problem occurs when creating the SignedContent
   */
  public SignedContent create_S1_O(Object content, 
                                   String contentType, 
                                   boolean implicitS1,
                                   X509Certificate[] signerCertificatesS1,
                                   PrivateKey signerPrivateKeyS1,
                                   AlgorithmID digestAlgS1,
                                   AlgorithmID signatureAlgS1,
                                   MLExpansionHistory mlExpansionHistoryS1) 
    throws MessagingException {
                                    
    return createSignedContent(content, 
                               contentType, 
                               implicitS1, 
                               signerCertificatesS1, 
                               signerPrivateKeyS1, 
                               digestAlgS1, 
                               signatureAlgS1,
                               mlExpansionHistoryS1);                                  
  }                                    
  
  /**
   * Triple-signs the given content.
   *
   * @param content the content to be signed
   * @param contentType the MIME type of the content
   * @param implicitS1 if the first signature shall be implicit (application/pkcs7-mime) or 
   *                   explicit (multipart/signed) 
   * @param signerCertificatesS1 the certificate chain of the first signer
   * @param signerPrivateKeyS1 the private key of the first signer
   * @param digestAlgS1 the digest algorithm to be used for digest calculation by the innermost SignedContent
   * @param signatureAlgS1 the algorithm to be used for signature calculation by the innermost SignedContent
   * @param mlExpansionHistoryS1 MLExpansionHistory attribute to be added to the innermost SignedContent; maybe null
   * @param implicitS2 if the second signature shall be implicit (application/pkcs7-mime) or 
   *                   explicit (multipart/signed) 
   * @param signerCertificatesS2 the certificate chain of the second signer
   * @param signerPrivateKeyS2 the private key of the second signer
   * @param digestAlgS2 the digest algorithm to be used for digest calculation by the middle SignedContent
   * @param signatureAlgS2 the algorithm to be used for signature calculation by the middle SignedContent
   * @param mlExpansionHistoryS2 MLExpansionHistory attribute to be added to the middle SignedContent; maybe null
   * @param implicitS3 if the first signature shall be implicit (application/pkcs7-mime) or 
   *                   explicit (multipart/signed) 
   * @param signerCertificatesS3 the certificate chain of the third signer
   * @param signerPrivateKeyS3 the private key of the third signer
   * @param digestAlgS3 the digest algorithm to be used for digest calculation by the outermost SignedContent
   * @param signatureAlgS3 the algorithm to be used for signature calculation by the outermost SignedContent
   * @param mlExpansionHistoryS3 MLExpansionHistory attribute to be added for the outermost SignedContent; maybe null
   *
   * @return the SignedContent
   *
   * @exception MessagingException if a problem occurs when creating the SignedContent
   */
  public SignedContent create_S3_S2_S1_O(Object content, 
                                         String contentType, 
                                         boolean implicitS1,
                                         X509Certificate[] signerCertificatesS1,
                                         PrivateKey signerPrivateKeyS1,
                                         AlgorithmID digestAlgS1,
                                         AlgorithmID signatureAlgS1,
                                         MLExpansionHistory mlExpansionHistoryS1,
                                         boolean implicitS2,
                                         X509Certificate[] signerCertificatesS2,
                                         PrivateKey signerPrivateKeyS2,
                                         AlgorithmID digestAlgS2,
                                         AlgorithmID signatureAlgS2,
                                         MLExpansionHistory mlExpansionHistoryS2,
                                         boolean implicitS3,
                                         X509Certificate[] signerCertificatesS3,
                                         PrivateKey signerPrivateKeyS3,
                                         AlgorithmID digestAlgS3,
                                         AlgorithmID signatureAlgS3,
                                         MLExpansionHistory mlExpansionHistoryS3) 
     throws MessagingException {
     SignedContent s1 = create_S1_O(content, contentType, 
                                    implicitS1, signerCertificatesS1, signerPrivateKeyS1, digestAlgS1, signatureAlgS1, mlExpansionHistoryS1); 
     SignedContent s2 = createSignedContent(s1, s1.getContentType(), 
                                            implicitS2, signerCertificatesS2, signerPrivateKeyS2, digestAlgS2, signatureAlgS2, mlExpansionHistoryS2);                            
     return createSignedContent(s2, s2.getContentType(), 
                                implicitS3, signerCertificatesS3, signerPrivateKeyS3, digestAlgS3, signatureAlgS3, mlExpansionHistoryS3);                                                          
  }  
  
  /**
   * Encrypts and signs the given content.
   *
   * @param content the content to be signed
   * @param contentType the MIME type of the content
   * @param implicitS1 whether to create an implicit (application/pkcs7-mime) or 
   *                 explicit (multipart/signed) message
   * @param signerCertificatesS1 the certificate chain of the signer
   * @param signerPrivateKeyS1 the private key to be used for signing the content
   * @param digestAlgS1 the algorithm to be used for digest calculation
   * @param signatureAlgS1 the algorithm to be used for signature calculation
   * @param mlExpansionHistoryS1 MLExpansionHistory attribute to be added; maybe null
   * @param recipientCertificate the encryption certificate of the recipient
   * @param cekEncrAlg the algorithm to be used for encrypting the symmetric content encryption key
   *                   (e.g. AlgorithmID.rsaEncryption)
   * @param contentEncrAlg the symmetric key to be used for encrypting the content, e.g. AlgorithmID.des_EDE3_CBC
   * @param cekLength the length of the temporary content encryption key to be generated (e.g. 192)
   *
   * @return the signed and encrypted message
   *
   * @exception MessagingException if a problem occurs when creating the SignedContent or EncryptedContent
   */
  public EncryptedContent create_E1_S1_O(Object content, 
                                         String contentType, 
                                         boolean implicitS1,
                                         X509Certificate[] signerCertificatesS1,
                                         PrivateKey signerPrivateKeyS1,
                                         AlgorithmID digestAlgS1,
                                         AlgorithmID signatureAlgS1,
                                         MLExpansionHistory mlExpansionHistoryS1,
                                         X509Certificate recipientCertificate,
                                         AlgorithmID cekEncrAlg,
                                         AlgorithmID contentEncrAlg,
                                         int cekLength) 
     throws MessagingException {
        
     SignedContent s1 = create_S1_O(content, contentType, 
                                    implicitS1, signerCertificatesS1, signerPrivateKeyS1, digestAlgS1, signatureAlgS1, mlExpansionHistoryS1); 
     return createEncryptedContent(s1, s1.getContentType(), 
                                   recipientCertificate, cekEncrAlg, contentEncrAlg, cekLength);                                       
  }    
  
  
  /**
   * Signs and encrypts and signs the given content.
   *
   * @param content the content to be signed
   * @param contentType the MIME type of the content
   * @param implicitS1 if the first signature shall be implicit (application/pkcs7-mime) or 
   *                   explicit (multipart/signed) 
   * @param signerCertificatesS1 the certificate chain of the first signer
   * @param signerPrivateKeyS1 the private key of the first signer
   * @param digestAlgS1 the digest algorithm to be used for digest calculation by the innermost SignedContent
   * @param signatureAlgS1 the algorithm to be used for signature calculation by the innermost SignedContent
   * @param mlExpansionHistoryS1 MLExpansionHistory attribute to be added to the innermost SignedContent; maybe null
   * @param recipientCertificate the encryption certificate of the recipient
   * @param cekEncrAlg the algorithm to be used for encrypting the symmetric content encryption key
   *                   (e.g. AlgorithmID.rsaEncryption)
   * @param contentEncrAlg the symmetric key to be used for encrypting the content, e.g. AlgorithmID.des_EDE3_CBC
   * @param cekLength the length of the temporary content encryption key to be generated (e.g. 192)
   * @param implicitS2 if the second signature shall be implicit (application/pkcs7-mime) or 
   *                   explicit (multipart/signed) 
   * @param signerCertificatesS2 the certificate chain of the second signer
   * @param signerPrivateKeyS2 the private key of the second signer
   * @param digestAlgS2 the digest algorithm to be used for digest calculation by the outer SignedContent
   * @param signatureAlgS2 the algorithm to be used for signature calculation by the outer SignedContent
   * @param mlExpansionHistoryS2 MLExpansionHistory attribute to be added to the outer SignedContent; maybe null
   *
   * @return the signed and encrypted and signed message
   *
   * @exception MessagingException if a problem occurs when creating a SignedContent or EncryptedContent
   */
  public SignedContent create_S2_E1_S1_0(Object content, 
                                         String contentType, 
                                         boolean implicitS1,
                                         X509Certificate[] signerCertificatesS1,
                                         PrivateKey signerPrivateKeyS1,
                                         AlgorithmID digestAlgS1,
                                         AlgorithmID signatureAlgS1,
                                         MLExpansionHistory mlExpansionHistoryS1,
                                         X509Certificate recipientCertificate,
                                         AlgorithmID cekEncrAlg,
                                         AlgorithmID contentEncrAlg,
                                         int cekLength,
                                         boolean implicitS2,
                                         X509Certificate[] signerCertificatesS2,
                                         PrivateKey signerPrivateKeyS2,
                                         AlgorithmID digestAlgS2,
                                         AlgorithmID signatureAlgS2,
                                         MLExpansionHistory mlExpansionHistoryS2) 
    throws MessagingException {
        
    EncryptedContent e1 = create_E1_S1_O(content, 
                                         contentType, 
                                         implicitS1,
                                         signerCertificatesS1,
                                         signerPrivateKeyS1,
                                         digestAlgS1,
                                         signatureAlgS1,
                                         mlExpansionHistoryS1,
                                         recipientCertificate,
                                         cekEncrAlg,
                                         contentEncrAlg,
                                         cekLength);
    return createSignedContent(e1, e1.getContentType(), 
                               implicitS2, signerCertificatesS2, signerPrivateKeyS2, digestAlgS2, signatureAlgS2, mlExpansionHistoryS2);                                     
  }      
  
  /**
   * Signs and encrypts and double-signs the given content.
   *
   * @param content the content to be signed
   * @param contentType the MIME type of the content
   * @param implicitS1 if the first signature shall be implicit (application/pkcs7-mime) or 
   *                   explicit (multipart/signed) 
   * @param signerCertificatesS1 the certificate chain of the first signer
   * @param signerPrivateKeyS1 the private key of the first signer
   * @param digestAlgS1 the digest algorithm to be used for digest calculation by the innermost SignedContent
   * @param signatureAlgS1 the algorithm to be used for signature calculation by the innermost SignedContent
   * @param mlExpansionHistoryS1 MLExpansionHistory attribute to be added to the innermost SignedContent; maybe null
   * @param recipientCertificate the encryption certificate of the recipient
   * @param cekEncrAlg the algorithm to be used for encrypting the symmetric content encryption key
   *                   (e.g. AlgorithmID.rsaEncryption)
   * @param contentEncrAlg the symmetric key to be used for encrypting the content, e.g. AlgorithmID.des_EDE3_CBC
   * @param cekLength the length of the temporary content encryption key to be generated (e.g. 192)
   * @param implicitS2 if the second signature shall be implicit (application/pkcs7-mime) or 
   *                   explicit (multipart/signed) 
   * @param signerCertificatesS2 the certificate chain of the second signer
   * @param signerPrivateKeyS2 the private key of the second signer
   * @param digestAlgS2 the digest algorithm to be used for digest calculation by the middle SignedContent
   * @param signatureAlgS2 the algorithm to be used for signature calculation by the middle SignedContent
   * @param mlExpansionHistoryS2 MLExpansionHistory attribute to be added to the middle SignedContent; maybe null
   * @param implicitS3 if the first signature shall be implicit (application/pkcs7-mime) or 
   *                   explicit (multipart/signed) 
   * @param signerCertificatesS3 the certificate chain of the third signer
   * @param signerPrivateKeyS3 the private key of the third signer
   * @param digestAlgS3 the digest algorithm to be used for digest calculation by the outermost SignedContent
   * @param signatureAlgS3 the algorithm to be used for signature calculation by the outermost SignedContent
   * @param mlExpansionHistoryS3 MLExpansionHistory attribute to be added for the outermost SignedContent; maybe null
   *
   * @return the signed and encrypted and double-signed message
   *
   * @exception MessagingException if a problem occurs when creating a SignedContent or EncryptedContent
   */
  public SignedContent create_S3_S2_E1_S1_0(Object content, 
                                           String contentType, 
                                           boolean implicitS1,
                                           X509Certificate[] signerCertificatesS1,
                                           PrivateKey signerPrivateKeyS1,
                                           AlgorithmID digestAlgS1,
                                           AlgorithmID signatureAlgS1,
                                           MLExpansionHistory mlExpansionHistoryS1,
                                           X509Certificate recipientCertificate,
                                           AlgorithmID cekEncrAlg,
                                           AlgorithmID contentEncrAlg,
                                           int cekLength,
                                           boolean implicitS2,
                                           X509Certificate[] signerCertificatesS2,
                                           PrivateKey signerPrivateKeyS2,
                                           AlgorithmID digestAlgS2,
                                           AlgorithmID signatureAlgS2,
                                           MLExpansionHistory mlExpansionHistoryS2,
                                           boolean implicitS3,
                                           X509Certificate[] signerCertificatesS3,
                                           PrivateKey signerPrivateKeyS3,
                                           AlgorithmID digestAlgS3,
                                           AlgorithmID signatureAlgS3,
                                           MLExpansionHistory mlExpansionHistoryS3) 
    throws MessagingException {
        
    SignedContent s2 = create_S2_E1_S1_0(content, 
                                         contentType, 
                                         implicitS1,
                                         signerCertificatesS1,
                                         signerPrivateKeyS1,
                                         digestAlgS1,
                                         signatureAlgS1,
                                         mlExpansionHistoryS1,
                                         recipientCertificate,
                                         cekEncrAlg,
                                         contentEncrAlg,
                                         cekLength,
                                         implicitS2,
                                         signerCertificatesS2,
                                         signerPrivateKeyS2,
                                         digestAlgS2,
                                         signatureAlgS2,
                                         mlExpansionHistoryS2) ;
    
    return createSignedContent(s2, s2.getContentType(), 
                               implicitS3, signerCertificatesS3, signerPrivateKeyS3, digestAlgS3, signatureAlgS3, mlExpansionHistoryS3);                                     
  }      
  
  /**
   * Decrypts the encrypted content with the given key of the identified recipient.
   * 
   * @param ec the EncryptedContent to be decrypted
   * @param privateKey the private key to be used to decrypt the encrypted content
   * @param certificate the certificate identifying the recipient for which to decrypt the encrypted content
   *
   * @return the DataHandler holding the recovered (decrypted) content
   *
   * @exception SMimeException if an error occurs while decrypting the content
   */
  public DataHandler decrypt(EncryptedContent ec, PrivateKey privateKey, X509Certificate certificate)
    throws SMimeException {
    try {    
      ec.decryptSymmetricKey(privateKey, certificate);
      return ec.getDataHandler();
    } catch (Exception ex) {
      throw new SMimeException(ex.toString());   
    }    
  }  
  
  /**
   * Verifies the signature of the given SignedContent and returns the inherent content data.
   * 
   * @param sc the SignedContent to be verified
   * @param signerCert the certificate of the signer (to check if the message has been signed
   *                                                  by the expected entity)
   * @return the inherent content data
   * @exception CMSSignatureException if the signature is invalid
   * @exception ESSException if an error occurs when accessing the inherent content or
   *                         the message has been signed by an unexpected entity
   * @exception MessagingException if an error occurs when accessing the content
    */
  public DataHandler verify(SignedContent sc, X509Certificate signerCert) 
    throws CMSSignatureException, MessagingException, ESSException {
        
    X509Certificate signer = sc.verify(); 
    System.out.println("Signature ok from: "+signer.getSubjectDN());
    if (signer.equals(signerCert) == false) {
      throw new ESSException("Error: message signed by wrong entity (" + signer.getSubjectDN() + ").\nExpected "
                              + signerCert.getSubjectDN());  
    }    
    return sc.getDataHandler();
  }  
  
  /**
   * Dumps the content of the original multipart message.
   * 
   * @param dh the dataHandler supplying the content of the original message
   * @exception IOException if an I/O error occurs while dumping the content
   * @exception MessagingException if an error occurs while reading the body parts of the message
   */
  public void dumpContent(DataHandler dh) throws IOException, MessagingException {
    Multipart mp = (Multipart)dh.getContent(); 
    System.out.println("Content is multipart (" + mp.getContentType() + ").");
    BodyPart bp1 = mp.getBodyPart(0);
    System.out.println("Content of first bodypart  (" + bp1.getContentType() + "):");
    System.out.println(bp1.getContent());
    BodyPart bp2 = mp.getBodyPart(1);
    System.out.println("Content of second bodypart  (" + bp2.getContentType() + "):");
    System.out.println(bp2.getContent());
    
  }  
  
  public SignedContent processMessageForMLA(Message msg, boolean implicit, String debugID) throws ESSLayerException, ESSException {
    
    // resolve the message into its layers
    ESSLayers layers = mla_.resolve(msg, debugID);
    try {
      return mla_.createSignedContent(signerPrivateKeyOfMLA_,
                                      new Date(),
                                      signerCertificatesOfMLA_[0], 
                                      signerCertificatesOfMLA_, 
                                      (AlgorithmID)AlgorithmID.sha1.clone(), 
                                      (AlgorithmID)AlgorithmID.rsaEncryption.clone(),
                                      encryptionCertificatesOfMLA_[0],
                                      true, 
                                      implicit,
                                      layers);
    } catch (Exception ex) {
      throw new ESSException("Error signing content: " + ex.toString()); 
    }  
  }  
  
  /**
   * Gets the data source encoding from the given data handler.
   *
   * @param dh the data handler from which to get the data source
   * 
   * @return the dataSource encoding; used for comparison
   *
   * @exception IOExceptio if an error occurs when reading the datasource
   */
  private byte[] getDataSource(DataHandler dh) throws IOException {
    DataSource ds = dh.getDataSource();
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    Utils.copyStream(ds.getInputStream(), baos, null);
    return baos.toByteArray();
  }  

  
  
  /**
   * Creates a MLExpansionHistory containing only one MLData for
   * the given MLA with given expansion time and MLReceiptPolicy.
   *
   * @param mlaCertificate the certificate of the MLA from which to create the
   *        MLData EntityIdentiifier of type IssuerAndSerialNumber
   * @param expansionTime the expansion time
   * @param mlReceiptPolicy the MLReceiptPolicy; may be null
   *
   * @return the newly created MLExpansionHistory
   */
  public static MLExpansionHistory createMLExpansionHistory(X509Certificate mlaCertificate,
                                                     Date expansionTime,
                                                     MLReceiptPolicy mlReceiptPolicy) {
    
    IssuerAndSerialNumber ias = new IssuerAndSerialNumber(mlaCertificate);
    MLData mlData = new MLData(new EntityIdentifier(ias), expansionTime); 
    mlData.setMLReceiptPolicy(mlReceiptPolicy);
    return new MLExpansionHistory(mlData);
  }                                                       
  
  /**
   * Reads the MLExpansionHistory attribute from the given signed data and dumps the 
   * included MLData structures.
   *
   * @param signedContent the (MLA created) SignedContent to be parsed for the MLExpansionHistory
   *                      attribute
   * @param count the (expected) number of MLData entries included in the MLExpansionHistory attribute
   *
   * @exception Exception if an error occurs when parsing the MLExpansionHistory attribute, or if
   *                      no MLExpansionHistory attribute is inlcuded or if the MLExpansionHistory
   *                      does contain an unexpected number of MLData entries
   */
  public static void readMLExpansionHistory(SignedContent signedContent, int count) throws Exception {
    SignerInfo signerInfo = signedContent.getSignerInfos()[0]; 
    MLExpansionHistory mlExpansionHistory = (MLExpansionHistory)signerInfo.getSignedAttributeValue(MLExpansionHistory.oid);
    if (mlExpansionHistory == null) {
      throw new Exception("Missing MLExpansionHistory attribute");   
    }    
    int size = mlExpansionHistory.countMLDataEntries();
    if (count != size) {
      throw new Exception("Invalid number (" + size + ") of MLData entries. Expected " + count);   
    }    
    System.out.println(mlExpansionHistory.toString(true));
  }  
  
  /** 
   * Prints a dump of the given message to System.out.
   *
   * @param msg the message to be dumped to System.out
   */
  private static void dumpMessage(Message msg) throws IOException {
    System.out.println("******************************************************************");
    System.out.println("Message dump: \n");
    try {
      msg.writeTo(System.out);
    } catch (MessagingException ex) {
      throw new IOException(ex.getMessage());   
    }    
    System.out.println("\n******************************************************************");
  }  
  
  /**
   * Main method.
   */
  public static void main(String[] argv) throws Exception {
    try {
      DemoSMimeUtil.initDemos();
      (new MLADemo()).start();
    } catch (Exception ex) {
      ex.printStackTrace();   
    }	    
    DemoUtil.waitKey();
  }
}
