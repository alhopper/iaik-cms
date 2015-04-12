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
// $Header: /IAIK-CMS/current/src/demo/cms/signedData/SignedDataStreamDemoWithAdditionalSignerInfo.java 19    23.08.13 14:29 Dbratko $
// $Revision: 19 $
//

package demo.cms.signedData;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.cms.CMSException;
import iaik.cms.DefaultSDSEncodeListener;
import iaik.cms.IssuerAndSerialNumber;
import iaik.cms.SignedDataStream;
import iaik.cms.SignerInfo;
import iaik.cms.attributes.CMSContentType;
import iaik.cms.attributes.SigningTime;
import iaik.utils.Util;
import iaik.x509.X509Certificate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;

import demo.DemoUtil;
import demo.keystore.CMSKeyStore;

/**
 * This class demonstrates the usage of an SDSEncodeListener to add a new SignerInfo to an
 * existing, parsed SignedDataStream object.
 * <p>
 * A {@link iaik.cms.SDSEncodeListener SDSEncodeListener} allows an application to update 
 * a {@link iaik.cms.SignedDataStream SignedDataStream} during the encoding phase.
 * <p>
 * In some situations it may be useful to supply information to a SignedDataStream
 * actually during encoding is performed. When implementing an SignedDataStream
 * encode listener an application has the chance to update the SignedDataStream
 * at two points during the encoding process: AFTER the content data has been
 * processed and any digest has been calulated (= BEFORE any signature value
 * is computed) and AFTER the signature values have been calculated. When doing
 * so an application has to implement two abstract methods: {@link 
 * iaik.cms.SDSEncodeListener#beforeComputeSignature(SignedDataStream) beforeComputeSignature} and 
 * {@link iaik.cms.SDSEncodeListener#afterComputeSignature(SignedDataStream) afterComputeSignature}
 * (of course, an application may implement any of the two methods in a 
 * way to do actually nothing (if no functionality is required)).
 * <p>
 * This demo uses the IAIK-CMS {@link iaik.cms.DefaultSDSEncodeListener DefaultSDSEncodeListener}
 * for adding a new SignerInfo to an already existing SignedDataStream "on the fly".
 *
 * @see iaik.cms.SignedDataStream
 * @see iaik.cms.SDSEncodeListener
 * 
 * @author Dieter Bratko
 */
public class SignedDataStreamDemoWithAdditionalSignerInfo {

  byte[] message;
  
  // signing certificate of user 1
  X509Certificate user1_sign;
  // signing private key of user 1
  PrivateKey user1_sign_pk;
  // signing certificate of user 2
  X509Certificate user2_sign;
  // signing private key of user 2
  PrivateKey user2_sign_pk;
  
  // a certificate chain containing the user certs + CA
  X509Certificate[] certificates;

  /**
   * Constructor.
   * Reads required keys/certs from the demo keystore.
   */
  public SignedDataStreamDemoWithAdditionalSignerInfo() {
    
    System.out.println();
    System.out.println("****************************************************************************************");
    System.out.println("*                       SignedDataStreamDemoWithAdditionalSignerInfo                   *");
    System.out.println("*  (shows how to use a SDSEncodeListener for the CMS SignedDataStream implementation)  *");
    System.out.println("****************************************************************************************");
    System.out.println();
    
    message = "This is a test of the CMS implementation!".getBytes();
    // signing certs
    certificates = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    user1_sign = certificates[0];
    user1_sign_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    user2_sign = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_2048_SIGN)[0];
    user2_sign_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_2048_SIGN);
  }
  
  /**
   * Creates a CMS <code>SignedData</code> object.
   * <p>
   *
   * @param message the message to be signed, as byte representation
   * @param mode the mode indicating whether to include the content 
   *        (SignedDataStream.IMPLICIT) or not (SignedDataStream.EXPLICIT)
   * @return the encoding of the <code>SignedData</code> object just created
   * @exception CMSException if the <code>SignedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createSignedDataStream(byte[] message, int mode) throws CMSException, IOException  {

    System.out.println("Create a new message signed by user 1:");

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);
    // create a new SignedData object which includes the data
    SignedDataStream signed_data = new SignedDataStream(is, mode);
    
    // uses SDSEncodeListener here only to verify sigantures before finishing encoding
    try {
      signed_data.setSDSEncodeListener(new DefaultSDSEncodeListener());
    } catch (NoSuchAlgorithmException ex) {
      // ignore here  
    }
    
    // SignedData shall include the certificate chain for verifying
    signed_data.setCertificates(certificates);

    // cert at index 0 is the user certificate
    IssuerAndSerialNumber issuer = new IssuerAndSerialNumber(user1_sign);

    // create a new SignerInfo
    SignerInfo signer_info = new SignerInfo(issuer, (AlgorithmID)AlgorithmID.sha256.clone(), user1_sign_pk);
    
    // create some signed attributes
    // the message digest attribute is automatically added
    Attribute[] attributes = new Attribute[2];
    try {
      // content type is data
      CMSContentType contentType = new CMSContentType(ObjectID.cms_data);
      attributes[0] = new Attribute(contentType);
      // signing time is now
      SigningTime signingTime = new SigningTime();
      attributes[1] = new Attribute(signingTime);
    } catch (Exception ex) {
      throw new CMSException("Error creating attribute: " + ex.toString());   
    }
    
    // set the attributes
    signer_info.setSignedAttributes(attributes);
    // finish the creation of SignerInfo by calling method addSigner
    try {
      signed_data.addSignerInfo(signer_info);

    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("No implementation for signature algorithm: "+ex.getMessage());
    }
    // ensure block encoding
    signed_data.setBlockSize(2048);

    // write the data through SignedData to any out-of-band place
    if (mode == SignedDataStream.EXPLICIT) {
      InputStream data_is = signed_data.getInputStream();
      byte[] buf = new byte[1024];
      int r;
      while ((r = data_is.read(buf)) > 0)
        ;   // skip data
    }

    // return the SignedData as encoded byte array with block size 2048
    ByteArrayOutputStream os = new ByteArrayOutputStream();

    signed_data.writeTo(os);
    return os.toByteArray();
  }

  /**
   * Parses a CMS <code>SignedData</code> object and verifies the signatures
   * for all participated signers. 
   *
   * @param signedData the SignedData, as BER encoded byte array
   * @param message the the message which was transmitted out-of-band (explicit signed)
   * @param writeAgain whether to use a SDSEncodeListener to add a SignerInfo
   *        and encode the SignedData again
   *
   * @return the inherent message as byte array, or the BER encoded SignedData if
   *         it shall be encoded again
   * @exception CMSException if any signature does not verify
   * @exception IOException if an I/O error occurs
   */
  public byte[] getSignedDataStream(byte[] signedData, byte[] message, boolean writeAgain) 
    throws CMSException, IOException, NoSuchAlgorithmException {

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(signedData);
    
    // the ByteArrayOutputStream to which to write the content
    ByteArrayOutputStream os = new ByteArrayOutputStream();
        
    SignedDataStream signed_data = new SignedDataStream(is);
    
    if (signed_data.getMode() == SignedDataStream.EXPLICIT) {
      // in explicit mode explicitly supply the content for hash computation  
      signed_data.setInputStream(new ByteArrayInputStream(message));
    }
    
    if (writeAgain) {
      // we want to write the SignedData again   
      // create a new SignerInfo
      SignerInfo signer_info = new SignerInfo(new IssuerAndSerialNumber(user2_sign),
                                              (AlgorithmID)AlgorithmID.sha256.clone(),
                                              user2_sign_pk);
     
      // create some signed attributes
      // the message digest attribute is automatically added
      Attribute[] attributes = new Attribute[2];
      try {
        // content type is data
        CMSContentType contentType = new CMSContentType(ObjectID.cms_data);
        attributes[0] = new Attribute(contentType);
        // signing time is now
        SigningTime signingTime = new SigningTime();
        attributes[1] = new Attribute(signingTime);
      } catch (Exception ex) {
        throw new CMSException("Error creating attribute: " + ex.toString());   
      }
      // set the attributes
      signer_info.setSignedAttributes(attributes);
      
      // add the SignerInfo via SDSEncodeListener which also verifies the sigantures
      DefaultSDSEncodeListener dl = new DefaultSDSEncodeListener();
      dl.setDigestAlgorithms(new AlgorithmID [] { (AlgorithmID)AlgorithmID.sha256.clone() });
      dl.setSignerInfos(new SignerInfo[] { signer_info });
      dl.setCertificates(new Certificate[] { user2_sign });
      
      
      if (message == null) {
        // in implicit mode copy data to os
        dl.setOutputStream(os);
        signed_data.setSDSEncodeListener(dl);     

      } else {
        signed_data.setSDSEncodeListener(dl);
        // get an InputStream for reading the signed content
        InputStream data = signed_data.getInputStream();
        Util.copyStream(data, os, null);
      } 
       
      // ensure block encoding
      signed_data.setBlockSize(2048);
      // return the SignedData as encoded byte array with block size 2048
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      signed_data.writeTo(baos);
      
      // we read the content
      byte[] content = os.toByteArray();
      System.out.println("Content: " + new String(content));
      
      return baos.toByteArray();

    } else {  

      // get an InputStream for reading the signed content
      InputStream data = signed_data.getInputStream();
      os = new ByteArrayOutputStream();
      Util.copyStream(data, os, null);

      System.out.println("SignedData contains the following signer information:");
      SignerInfo[] signer_infos = signed_data.getSignerInfos();

      for (int i=0; i<signer_infos.length; i++) {
        try {
          // verify the signed data using the SignerInfo at index i
          X509Certificate signer_cert = signed_data.verify(i);
          // if the signature is OK the certificate of the signer is returned
          System.out.println("Signature OK from signer: "+signer_cert.getSubjectDN());
          // get signed attributes
          SigningTime signingTime = (SigningTime)signer_infos[i].getSignedAttributeValue(ObjectID.signingTime);
          if (signingTime != null) {
            System.out.println("This message has been signed at " + signingTime.get());
          } 
          CMSContentType contentType = (CMSContentType)signer_infos[i].getSignedAttributeValue(ObjectID.contentType);
          if (contentType != null) {
            System.out.println("The content has CMS content type " + contentType.get().getName());
          }

        } catch (SignatureException ex) {
          // if the signature is not OK a SignatureException is thrown
          System.out.println("Signature ERROR from signer: "+signed_data.getCertificate((signer_infos[i].getSignerIdentifier())).getSubjectDN());
          throw new CMSException(ex.toString());
        } 
      }
      // now check alternative signature verification
      System.out.println("Now check the signature assuming that no certs have been included:");
      try {
        SignerInfo signer_info = signed_data.verify(user1_sign);
        // if the signature is OK the certificate of the signer is returned
        System.out.println("Signature OK from signer: "+signed_data.getCertificate(signer_info.getSignerIdentifier()).getSubjectDN());

      } catch (SignatureException ex) {
        // if the signature is not OK a SignatureException is thrown
        System.out.println("Signature ERROR from signer: "+user1_sign.getSubjectDN());
        throw new CMSException(ex.toString());
      }

      try {
        SignerInfo signer_info = signed_data.verify(user2_sign);
        // if the signature is OK the certificate of the signer is returned
        System.out.println("Signature OK from signer: "+signed_data.getCertificate(signer_info.getSignerIdentifier()).getSubjectDN());

      } catch (SignatureException ex) {
        // if the signature is not OK a SignatureException is thrown
        System.out.println("Signature ERROR from signer: "+user2_sign.getSubjectDN());
        throw new CMSException(ex.toString());
      }
      return os.toByteArray();
    }
    
  }

  /** 
   * Starts the test.
   */
  public void start() {

    try {
        
      byte[] data;
      byte[] received_message = null;  
      
      
      //
      // test CMS Implicit SignedDataStream
      //
      System.out.println("\nImplicit SignedDataStream demo [create]:\n");
      data = createSignedDataStream(message, SignedDataStream.IMPLICIT);
      // parse and encode again
      System.out.println("\nImplicit SignedDataStream demo [write again]:\n");
      data = getSignedDataStream(data, null, true);
      // parse
      System.out.println("\nImplicit SignedDataStream demo [parse]:\n");
      received_message = getSignedDataStream(data, null, false);
      System.out.print("\nSigned content: ");
      System.out.println(new String(received_message));

      //
      // test CMS Explicit SignedDataStream
      //
      System.out.println("\nExplicit SignedDataStream demo [create]:\n");
      data = createSignedDataStream(message, SignedDataStream.EXPLICIT);
      // parse and encode again
      System.out.println("\nExplicit SignedDataStream demo [write again]:\n");
      data = getSignedDataStream(data, message, true);
      
      System.out.println("\nExplicit SignedDataStream demo [parse]:\n");
      received_message = getSignedDataStream(data, message, false);
      System.out.print("\nSigned content: ");
      System.out.println(new String(received_message));

   	} catch (Exception ex) {
   	  ex.printStackTrace();
   	  throw new RuntimeException(ex.toString());
   	}
	}

    
  /**
   * The main method.
   * 
   * @exception IOException 
   *            if an I/O error occurs when reading required keys
   *            and certificates from files
   */
  public static void main(String argv[]) throws IOException {
    try {
      DemoUtil.initDemos();
      (new SignedDataStreamDemoWithAdditionalSignerInfo()).start();
    } catch (Exception ex) {    
      ex.printStackTrace();
    }
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
