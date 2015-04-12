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
// $Header: /IAIK-CMS/current/src/demo/cms/tsp/TimeStampDemo.java 16    23.08.13 14:30 Dbratko $
// $Revision: 16 $
//

package demo.cms.tsp;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.cms.CMSException;
import iaik.cms.ContentInfo;
import iaik.cms.ContentInfoStream;
import iaik.cms.IssuerAndSerialNumber;
import iaik.cms.SignedData;
import iaik.cms.SignedDataStream;
import iaik.cms.SignerInfo;
import iaik.cms.attributes.CMSContentType;
import iaik.cms.attributes.SigningTime;
import iaik.tsp.TimeStampReq;
import iaik.tsp.TimeStampResp;
import iaik.utils.Util;
import iaik.x509.X509Certificate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;

import demo.DemoUtil;
import demo.keystore.CMSKeyStore;

/**
 * This demo shows how to add a time stamp to a SignedData message.
 * <p> 
 * For the stream-based part of this demo we use a SDSEncodeListener to add a 
 * SignatureTimeStampToken attribute the SignerInfo of a SignedDataStream object.
 * <p>
 * A {@link iaik.smime.attributes.SignatureTimeStampToken SignatureTimeStampToken} attribute may
 * be included as an unsigned attribute into a {@link iaik.cms.SignerInfo SignerInfo} for time stamping
 * the signature value of a SignerInfo included in a SignedData. Using an SignedDataStream encode 
 * listener for adding a SignatureTimeStampToken may be useful when having to time stamp the signature
 * calculated from a large data volume. Since reading all the data into memory may cause an OutOfMemory
 * problem, class {@link iaik.cms.SignedDataStream SignedDataStream} should to be used for 
 * creating/encoding the SignedData object and the SignatureTimeStampToken may be added by means
 * of a {@link iaik.cms.SDSEncodeListener SDSEncodeListener}.
 * <p>
 * The SDSEncodeListener used by this demo is implemented by class {@link demo.cms.tsp.TimeStampListener
 * TimeStampListener} assuming that only one SignerInfo is included in the SignedData.
 * This TSA from which to get the time stamp has to be provided by its HTTP URL, i.e. this demo
 * only works with time stamp authorities providing a HTTP service (like "http://tsp.iaik.at/tsp/TspRequest").
 * <p>
 * To run this demo, you must have the IAIK-TSP (2.x) library in your classpath.
 * You can get it from <a href = "http://jce.iaik.tugraz.at/sic/products/public_key_infrastructure/tsp">
 * http://jce.iaik.tugraz.at/sic/products/public_key_infrastructure/tsp</a>.  
 *
 * @see demo.cms.tsp.TimeStampListener
 * @see iaik.cms.SDSEncodeListener
 * @see iaik.cms.SignedDataStream
 * @see iaik.cms.SignedData
 * @see iaik.cms.SignerInfo 
 * @see iaik.smime.attributes.SignatureTimeStampToken
 * 
 * @author Dieter Bratko
 */
public class TimeStampDemo {
    
  /**
   * The (http) url where the time stamp service is running.
   */
  String tsaUrl_;  
      
  /**
   * The data to be signed.
   */ 
  byte[] message_;
  
  /**
   * The signer certificate chain.
   */ 
  X509Certificate[] signerCerts_;
  
  /**
   * Signer private key.
   */ 
  PrivateKey signerKey_;
  
  /**
   * Constructor.
   * Reads required keys/certs from the demo keystore.
   */
  public TimeStampDemo() {
    
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                           TimeStampDemo demo                                   *");
    System.out.println("*   (shows how to add a TimeStampToken attribute to a SignedDataStream object)   *");
    System.out.println("**********************************************************************************");
    System.out.println();
    
    message_ = "This is a test message!".getBytes();
    // signer certs
    signerCerts_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    // signer key
    signerKey_ = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
  }
  
  
  /**
   * Creates a CMS <code>SignedData</code> object (stream version) and adds
   * a TimeStampToken as unsigned attribute.
   * <p>
   *
   * @param message the message to be signed, as byte representation
   * @param mode the mode indicating whether to include the content 
   *        (SignedDataStream.IMPLICIT) or not (SignedDataStream.EXPLICIT)
   * @return the encoding of the <code>SignedData</code> object just created
   * @exception Exception if the <code>SignedData</code> object cannot
   *                      be created for some reason
   */
  public byte[] createSignedDataStream(byte[] message, int mode) throws Exception {

    System.out.println("Create SignedData message...");

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);
    // create a new SignedData object 
    SignedDataStream signedData = new SignedDataStream(is, mode);
    
    // SignedData shall include the certificate chain for verifying
    signedData.setCertificates(signerCerts_);

    // signer cert is identifed by IssuerAndSerialNumber
    IssuerAndSerialNumber issuer = new IssuerAndSerialNumber(signerCerts_[0]);

    // create a new SignerInfo
    SignerInfo signerInfo = new SignerInfo(issuer, (AlgorithmID)AlgorithmID.sha1.clone(), signerKey_);
    // create some authenticated attributes
    // the message digest attribute is automatically added
    Attribute[] attributes = new Attribute[2];
    // content type is data
    attributes[0] = new Attribute(new CMSContentType(ObjectID.cms_data));
    // signing time is now
    attributes[1] = new Attribute(new SigningTime());
    // set the attributes
    signerInfo.setSignedAttributes(attributes);
    // finish the creation of SignerInfo by calling method addSigner
    try {
      signedData.addSignerInfo(signerInfo);

    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("No implementation for signature algorithm: "+ex.getMessage());
    }
    
    // create and add a TimeStampListener to include a TimeStampToken to be obtained from the specified TSA
    TimeStampListener tsl = new TimeStampListener(tsaUrl_);
    tsl.setDebugStream(System.out);
    signedData.setSDSEncodeListener(tsl);  

    // if content shall not be included write the data to any out-of-band place
    if (mode == SignedDataStream.EXPLICIT) {
      InputStream dataIs = signedData.getInputStream();
      byte[] buf = new byte[1024];
      int r;
      while ((r = dataIs.read(buf)) > 0)
        ;   // skip data
    }
    
    // ensure block encoding 
    signedData.setBlockSize(2048);
    // return the SignedData as encoded byte array
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    ContentInfoStream cis = new ContentInfoStream(signedData);
    cis.writeTo(os);
    return os.toByteArray();
  }

  /**
   * Parses a CMS <code>SignedData</code> object and verifies the signature.
   *
   * @param encoding the SignedData, as BER encoded byte array
   * @param message the message which was transmitted out-of-band (explicit signed), or <code>null</code>
   *                in implicit mode
   *
   * @return the content data as byte array
   *
   * @exception Exception if some error occurs
   */
  public byte[] getSignedDataStream(byte[] encoding, byte[] message) throws Exception {

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    
    // the ByteArrayOutputStream to which to write the content
    ByteArrayOutputStream os = new ByteArrayOutputStream();
        
    SignedDataStream signedData = new SignedDataStream(is);
    // in explcit mode supply the content data received by other means
    if (message != null) {
      signedData.setInputStream(new ByteArrayInputStream(message));
    }
    
    // get an InputStream for reading the signed content
    InputStream data = signedData.getInputStream();
    Util.copyStream(data, os, null);

    // in this demo we know that we have only one signer
    SignerInfo signerInfo = signedData.getSignerInfos()[0];
     
    try { 
      // verify the signature
      X509Certificate signerCert = signedData.verify(0);
      // if the signature is OK the certificate of the signer is returned
      System.out.println("Signature OK from signer: "+signerCert.getSubjectDN());
    } catch (SignatureException ex) {
      // if the signature is not OK a SignatureException is thrown
      System.out.println("Signature ERROR from signer: "+signedData.getCertificate((signerInfo.getSignerIdentifier())).getSubjectDN());
       throw new CMSException(ex.toString());
    }
    // get signed attributes
    // signing time
    SigningTime signingTime = (SigningTime)signerInfo.getSignedAttributeValue(ObjectID.signingTime);
    if (signingTime != null) {
      System.out.println("This message has been signed at " + signingTime.get());
    } 
    // content type
    CMSContentType contentType = (CMSContentType)signerInfo.getSignedAttributeValue(ObjectID.contentType);
    if (contentType != null) {
      System.out.println("The content has CMS content type " + contentType.get().getName());
    }
    // check SignatureTimeStampToken
    TSPDemoUtils.validateSignatureTimeStampToken(signerInfo);    
    return os.toByteArray();
  }
  
  /**
   * Creates a CMS <code>SignedData</code> object and adds a TimeStampToken as unsigned attribute.
   * <p>
   *
   * @param message the message to be signed, as byte representation
   * @param mode the mode indicating whether to include the content 
   *        (SignedData.IMPLICIT) or not (SignedData.EXPLICIT)
   * @return the encoding of the <code>SignedData</code> object just created
   * 
   * @exception Exception if the <code>SignedData</code> object cannot
   *                      be created for some reason
   */
  public byte[] createSignedData(byte[] message, int mode) throws Exception {

    System.out.println("Create SignedData message...");

    // create a new SignedData object 
    SignedData signedData = new SignedData(message, mode);
    
    // SignedData shall include the certificate chain for verifying
    signedData.setCertificates(signerCerts_);

    // signer cert is identifed by IssuerAndSerialNumber
    IssuerAndSerialNumber issuer = new IssuerAndSerialNumber(signerCerts_[0]);

    // create a new SignerInfo
    SignerInfo signerInfo = new SignerInfo(issuer, (AlgorithmID)AlgorithmID.sha1.clone(), signerKey_);
    // create some signed attributes
    // the message digest attribute is automatically added
    Attribute[] attributes = new Attribute[2];
    // content type is data
    attributes[0] = new Attribute(new CMSContentType(ObjectID.cms_data));
    // signing time is now
    attributes[1] = new Attribute(new SigningTime());
    // set the attributes
    signerInfo.setSignedAttributes(attributes);
    // finish the creation of SignerInfo by calling method addSigner
    try {
      signedData.addSignerInfo(signerInfo);

    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("No implementation for signature algorithm: "+ex.getMessage());
    }
    
    // now (after signature is calculated by calling addSignerInfo) add time stamp
    System.out.println("Create time stamp request.");
    TimeStampReq request = TSPDemoUtils.createRequest(signerInfo, null);
    System.out.println("Send time stamp request to " + tsaUrl_);
    TimeStampResp response = TSPDemoUtils.sendRequest(request, tsaUrl_);
    // validate the response
    System.out.println("Validate response.");
    TSPDemoUtils.validateResponse(response, request);
    System.out.println("Response ok.");
    // add time stamp
    System.out.println("Add time stamp to SignerInfo.");
    TSPDemoUtils.timeStamp(response.getTimeStampToken(), signerInfo);

    // if content shall not be included write the data to any out-of-band place
    if (mode == SignedDataStream.EXPLICIT) {
      InputStream dataIs = signedData.getInputStream();
      byte[] buf = new byte[1024];
      int r;
      while ((r = dataIs.read(buf)) > 0)
        ;   // skip data
    }
    
    // return the SignedData as encoded byte array
    ContentInfo ci = new ContentInfo(signedData);
    return ci.getEncoded();
  }
  
  /**
   * Parses a CMS <code>SignedData</code> object and verifies the signature.
   *
   * @param encoding the SignedData, as BER encoded byte array
   * @param message the message which was transmitted out-of-band (explicit signed), or <code>null</code>
   *                in implicit mode
   *
   * @return the content data as byte array
   *
   * @exception Exception if some error occurs
   */
  public byte[] getSignedData(byte[] encoding, byte[] message) throws Exception {

    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    
    SignedData signedData = new SignedData(is);
    // in explcit mode supply the content data received by other means
    if (message != null) {
      signedData.setContent(message);
    }
    

    // in this demo we know that we have only one signer
    SignerInfo signerInfo = signedData.getSignerInfos()[0];
     
    try { 
      // verify the signature
      X509Certificate signerCert = signedData.verify(0);
      // if the signature is OK the certificate of the signer is returned
      System.out.println("Signature OK from signer: "+signerCert.getSubjectDN());
    } catch (SignatureException ex) {
      // if the signature is not OK a SignatureException is thrown
      System.out.println("Signature ERROR from signer: "+signedData.getCertificate((signerInfo.getSignerIdentifier())).getSubjectDN());
      throw new CMSException(ex.toString());
    }
    // get signed attributes
    // signing time
    SigningTime signingTime = (SigningTime)signerInfo.getSignedAttributeValue(ObjectID.signingTime);
    if (signingTime != null) {
      System.out.println("This message has been signed at " + signingTime.get());
    } 
    // content type
    CMSContentType contentType = (CMSContentType)signerInfo.getSignedAttributeValue(ObjectID.contentType);
    if (contentType != null) {
      System.out.println("The content has CMS content type " + contentType.get().getName());
    }
    // check SignatureTimeStampToken
    TSPDemoUtils.validateSignatureTimeStampToken(signerInfo);
    return signedData.getContent();
  }
  
  
  /**
   * Starts the demo.
   */
  public void start() {
    
    TSPServer.setDebugStream(System.out);
    final TSPServer tspServer = new TSPServer();
    
    // start TSP server in a separate thread
    new Thread() {
      public void run() {
         tspServer.start();    
      }
    }.start();
  
    // tsp server is running on local host
    tsaUrl_ = "http://localhost:" + tspServer.getPort();

    try {
        
      byte[] data;
      byte[] receivedMessage = null;  
      
      //
      // Implicit SignedDataStream
      //
      System.out.println("\nImplicit SignedDataStream TSP demo [create]:\n");
      data = createSignedDataStream(message_, SignedDataStream.IMPLICIT);
      // parse
      System.out.println("\nImplicit SignedDataStream TSP demo [parse]:\n");
      receivedMessage = getSignedDataStream(data, null);
      System.out.print("\nSigned content: ");
      System.out.println(new String(receivedMessage));

      //
      // Explicit SignedDataStream
      //
      System.out.println("\nExplicit SignedDataStream TSP demo [create]:\n");
      data = createSignedDataStream(message_, SignedDataStream.EXPLICIT);
      // parse
      System.out.println("\nExplicit SignedDataStream TSP demo [parse]:\n");
      receivedMessage = getSignedDataStream(data, message_);
      System.out.print("\nSigned content: ");
      System.out.println(new String(receivedMessage));
      
      // non stream
      
      //
      // Implicit SignedData
      //
      System.out.println("\nImplicit SignedData TSP demo [create]:\n");
      data = createSignedData(message_, SignedData.IMPLICIT);
      // parse
      System.out.println("\nImplicit SignedData TSP demo [parse]:\n");
      receivedMessage = getSignedData(data, null);
      System.out.print("\nSigned content: ");
      System.out.println(new String(receivedMessage));

      //
      // Explicit SignedData
      //
      System.out.println("\nExplicit SignedData TSP demo [create]:\n");
      data = createSignedData(message_, SignedData.EXPLICIT);
      // parse
      System.out.println("\nExplicit SignedData TSP demo [parse]:\n");
      receivedMessage = getSignedData(data, message_);
      System.out.print("\nSigned content: ");
      System.out.println(new String(receivedMessage));

      

   	} catch (Exception ex) {
   	  ex.printStackTrace();
   	  throw new RuntimeException(ex.toString());
   	} finally {
      // stop server
      tspServer.stop();
    }
  }

    
  /**
   * Main method.
   * 
   * @exception IOException 
   *            if an I/O error occurs when reading required keys
   *            and certificates from files
   */
  public static void main(String argv[]) throws IOException {
   try {
     DemoUtil.initDemos();
     (new TimeStampDemo()).start();
     System.out.println("\nReady!");
   } catch (Exception ex) {    
     ex.printStackTrace();      
   }
   
   DemoUtil.waitKey();
  }
}
