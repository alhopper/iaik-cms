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
// $Header: /IAIK-CMS/current/src/demo/cms/signedData/SHA2withDSASignedDataDemo.java 2     23.08.13 14:29 Dbratko $
// $Revision: 2 $
//

package demo.cms.signedData;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.cms.CMSException;
import iaik.cms.IssuerAndSerialNumber;
import iaik.cms.SignedData;
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

import demo.DemoUtil;
import demo.keystore.CMSKeyStore;


/**
 * Demonstrates the usage of class {@link iaik.cms.SignedDataStream} and
 * {@link iaik.cms.SignedData} for signing some data using the CMS type
 * SignedData with SHA2withDSA signature algorithm according to FIPS 186-3.
 * 
 * @author Dieter Bratko
 */
public class SHA2withDSASignedDataDemo {

  // The private key of the signer.
  PrivateKey signerKey_;

  // The certificate chain of the signer.
  X509Certificate[] signerCertificates_;


  
  /**
   * Setups the demo certificate chains.
   * 
   * Keys and certificate are retrieved from the demo KeyStore.
   * 
   * @exception IOException if an file read error occurs
   */
  public SHA2withDSASignedDataDemo() throws IOException {
    
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                        SHA2withDSASignedDataDemo                               *");
    System.out.println("*       (shows the usage of the CMS SignedData type with SHA2withDSA)            *");
    System.out.println("**********************************************************************************");
    System.out.println();
    
    // add all certificates to the list
    signerCertificates_ = CMSKeyStore.getCertificateChain(CMSKeyStore.DSA, CMSKeyStore.SZ_3072_SIGN);
    signerKey_ = CMSKeyStore.getPrivateKey(CMSKeyStore.DSA, CMSKeyStore.SZ_3072_SIGN);
  }
  
  /**
   * Creates a CMS <code>SignedData</code> object.
   * <p>
   *
   * @param message the message to be signed, as byte representation
   * @param mode the transmission mode, either IMPLICIT or EXPLICIT
   * @return the BER encoding of the <code>SignedData</code> object just created
   * @exception CMSException if the <code>SignedData</code> object cannot
   *                          be created
   * @exception IOException if some stream I/O error occurs
   */
  public byte[] createSignedDataStream(byte[] message, int mode) throws CMSException, IOException  {
    
    System.out.println("Create a new message signed by " + signerCertificates_[0].getSubjectDN());
   
    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);
    // create a new SignedData object which includes the data
    SignedDataStream signed_data = new SignedDataStream(is, mode);
    
    // SignedData shall include the certificate chain for verifying
    signed_data.setCertificates(signerCertificates_);
    
    // cert at index 0 is the signer certificate
    IssuerAndSerialNumber issuer = new IssuerAndSerialNumber(signerCertificates_[0]);

    // create a new SignerInfo
    SignerInfo signer_info = new SignerInfo(issuer,
                                            (AlgorithmID)AlgorithmID.sha256.clone(),
                                            (AlgorithmID)AlgorithmID.dsaWithSHA256.clone(),
                                            signerKey_);
    // create some authenticated attributes
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

    // write the data through SignedData to any out-of-band place
    if (mode == SignedDataStream.EXPLICIT) {
      InputStream data_is = signed_data.getInputStream();
      byte[] buf = new byte[1024];
      int r;
      while ((r = data_is.read(buf)) > 0)
        ;   // skip data
    }

    // return the SignedData as DER encoded byte array with block size 2048
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    signed_data.writeTo(os, 2048);
    return os.toByteArray();
  }
  

  /**
   * Parses a CMS <code>SignedData</code> object and verifies the signatures
   * for all participated signers.
   *
   * @param signedData <code>SignedData</code> object as BER encoded byte array
   * @param message the the message which was transmitted out-of-band (explicit signed)
   *
   * @return the inherent message as byte array
   * @exception CMSException if any signature does not verify
   * @exception IOException if some stream I/O error occurs
   */
  public byte[] getSignedDataStream(byte[] signedData, byte[] message) throws CMSException, IOException {

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(signedData);
    // create the SignedData object
    SignedDataStream signed_data = new SignedDataStream(is);
    
    if (signed_data.getMode() == SignedDataStream.EXPLICIT) {
      // in explicit mode explicitly supply the content for hash computation  
      signed_data.setInputStream(new ByteArrayInputStream(message));
    }

    // get an InputStream for reading the signed content
    InputStream data = signed_data.getInputStream();
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    Util.copyStream(data, os, null);
    
    System.out.println("SignedData contains the following signer information:");
    SignerInfo[] signer_infos = signed_data.getSignerInfos();
    
    for (int i=0; i<signer_infos.length; i++) {
      AlgorithmID signatureAlgorithm = signer_infos[i].getSignatureAlgorithm();  
      try {
        // verify the signed data using the SignerInfo at index i
        X509Certificate signer_cert = signed_data.verify(i);
        // if the signature is OK the certificate of the signer is returned
        System.out.println("Signature (" + signatureAlgorithm.getName() + ") OK from signer: "+signer_cert.getSubjectDN());
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
        System.out.println("Signature ERROR from signer: "+signed_data.getCertificate(signer_infos[i].getSignerIdentifier()).getSubjectDN());
        throw new CMSException(ex.toString());
      }  
    }  
    
    // now check alternative signature verification
    System.out.println("Now check the signature assuming that no certs have been included:");
    try {
       SignerInfo signer_info = signed_data.verify(signerCertificates_[0]);
       AlgorithmID signatureAlgorithm = signer_info.getSignatureAlgorithm();
       // if the signature is OK the certificate of the signer is returned
       System.out.println("Signature (" + signatureAlgorithm.getName() + ") OK from signer: "+signerCertificates_[0].getSubjectDN());
        
    } catch (SignatureException ex) {
        // if the signature is not OK a SignatureException is thrown
        System.out.println("Signature ERROR from signer: "+signerCertificates_[0].getSubjectDN());
        throw new CMSException(ex.toString());
    }
    return os.toByteArray();
  }
  
  
  
  /**
   * Creates a CMS <code>SignedData</code> object.
   * <p>
   *
   * @param message the message to be signed, as byte representation
   * @param mode the mode, either SignedData.IMPLICIT or SignedData.EXPLICIT
   * @return the DER encoded <code>SignedData</code> object
   * @exception CMSException if the <code>SignedData</code> object cannot
   *                          be created
   */
  public byte[] createSignedData(byte[] message, int mode) throws CMSException {
    
    System.out.println("Create a new message signed by " + signerCertificates_[0].getSubjectDN());
  
    // create a new SignedData object which includes the data
    SignedData signed_data = new SignedData(message, mode);
    
    // SignedData shall include the certificate chain for verifying
    signed_data.setCertificates(signerCertificates_);
  
    // cert at index 0 is the signer certificate
    IssuerAndSerialNumber issuer = new IssuerAndSerialNumber(signerCertificates_[0]);

    // create a new SignerInfo
    /*
    SignerInfo signer_info = new SignerInfo(issuer,
                                            (AlgorithmID)AlgorithmID.sha256.clone(),
                                            (AlgorithmID)AlgorithmID.dsaWithSHA256.clone(),
                                            signerKey_);
     */
    SignerInfo signer_info = new SignerInfo(issuer,
            (AlgorithmID)AlgorithmID.sha256.clone(),
            (AlgorithmID)AlgorithmID.dsaWithSHA256.clone(),
            signerKey_);

    // create some authenticated attributes
    // the message digest attribute is automatically added
    Attribute[] attributes = new Attribute[2];
    try {
      // content type is data
      CMSContentType contentType = new CMSContentType(ObjectID.cms_data);
      attributes[0] = new Attribute(contentType);
      // signing time is now
      SigningTime signingTime = new SigningTime();
      attributes[1] = new Attribute(signingTime);
      // signing certificate
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
    return signed_data.getEncoded();
  }
  
  
  /**
   * Parses a CMS <code>SignedData</code> object and verifies the signatures
   * for all participated signers.
   *
   * @param encoding the DER encoded <code>SignedData</code> object
   * @param message the the message which was transmitted out-of-band (explicit signed)
   *
   * @return the inherent message as byte array
   * @exception CMSException if any signature does not verify
   * @exception IOException if some stream I/O error occurs
   */
  public byte[] getSignedData(byte[] encoding, byte[] message) throws CMSException, IOException {
    
    ByteArrayInputStream encodedStream = new ByteArrayInputStream(encoding);
    // create the SignedData object
    SignedData signed_data = new SignedData(encodedStream);
    
    if (signed_data.getMode() == SignedData.EXPLICIT) {
      // in explcit mode explictly supply the content data to do the hash calculation
      signed_data.setContent(message);
    }
    
    System.out.println("SignedData contains the following signer information:");
    SignerInfo[] signer_infos = signed_data.getSignerInfos();
    
    for (int i=0; i<signer_infos.length; i++) {
      AlgorithmID signatureAlgorithm = signer_infos[i].getSignatureAlgorithm();
      try {
        // verify the signed data using the SignerInfo at index i
        X509Certificate signer_cert = signed_data.verify(i);
        // if the signature is OK the certificate of the signer is returned
        System.out.println("Signature (" + signatureAlgorithm.getName() + ") OK from signer: "+signer_cert.getSubjectDN());
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
         System.out.println("Signature ERROR from signer: "+signed_data.getCertificate(signer_infos[i].getSignerIdentifier()).getSubjectDN());
         throw new CMSException(ex.toString());
      } 
    }      
    
    // now check alternative signature verification
    System.out.println("Now check the signature assuming that no certs have been included:");
    try {
      SignerInfo signer_info = signed_data.verify(signerCertificates_[0]);
      AlgorithmID signatureAlgorithm = signer_info.getSignatureAlgorithm();
      // if the signature is OK the certificate of the signer is returned
      System.out.println("Signature (" + signatureAlgorithm.getName() + ") OK from signer: "+signed_data.getCertificate(signer_info.getSignerIdentifier()).getSubjectDN());
        
    } catch (SignatureException ex) {
      // if the signature is not OK a SignatureException is thrown
      System.out.println("Signature ERROR from signer: "+signerCertificates_[0].getSubjectDN());
      throw new CMSException(ex.toString());
    }
    
    return signed_data.getContent();
  }
 
  /**
   * Tests the CMS SignedData implementation.
   */
  public void start() {
     // the test message
    String m = "This is the test message.";
    System.out.println("Test message: \""+m+"\"");
    System.out.println();
    byte[] message = m.getBytes();
   
    try {
      byte[] encoding;
      byte[] received_message = null;
      System.out.println("Stream implementation demos");
      System.out.println("===========================");
      //
      // test CMS Implicit SignedDataStream
      //
      System.out.println("\nImplicit SignedDataStream demo [create]:\n");
      encoding = createSignedDataStream(message, SignedDataStream.IMPLICIT);
      // transmit data
      System.out.println("\nImplicit SignedDataStream demo [parse]:\n");
      received_message = getSignedDataStream(encoding, null);
      System.out.print("\nSigned content: ");
      System.out.println(new String(received_message));
      
      //
      // test CMS Explicit SignedDataStream
      //
      System.out.println("\nExplicit SignedDataStream demo [create]:\n");
      encoding = createSignedDataStream(message, SignedDataStream.EXPLICIT);
      // transmit data
      System.out.println("\nExplicit SignedDataStream demo [parse]:\n");
      received_message = getSignedDataStream(encoding, message);
      System.out.print("\nSigned content: ");
      System.out.println(new String(received_message));
            
      // the non-stream implementation
      System.out.println("\nNon-stream implementation demos");
      System.out.println("===============================");
   
      //
      // test CMS Implicit SignedData
      //
      System.out.println("\nImplicit CMS SignedData demo [create]:\n");
      encoding = createSignedData(message, SignedData.IMPLICIT);
      // transmit data
      System.out.println("\nImplicit CMS SignedData demo [parse]:\n");
      received_message = getSignedData(encoding, null);
      System.out.print("\nSigned content: ");
      System.out.println(new String(received_message));

      //
      // test CMS Explicit SignedData
      //
      System.out.println("\nExplicit CMS SignedData demo [create]:\n");
      encoding = createSignedData(message, SignedData.EXPLICIT);
      // transmit data
      System.out.println("\nExplicit CMS SignedData demo [parse]:\n");
      received_message = getSignedData(encoding, message);
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
  public static void main(String argv[]) throws Exception {

   	DemoUtil.initDemos();
    (new SHA2withDSASignedDataDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}