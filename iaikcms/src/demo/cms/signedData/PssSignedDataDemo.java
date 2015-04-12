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
// $Header: /IAIK-CMS/current/src/demo/cms/signedData/PssSignedDataDemo.java 14    23.08.13 14:29 Dbratko $
// $Revision: 14 $
//

package demo.cms.signedData;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.cms.CMSException;
import iaik.cms.IssuerAndSerialNumber;
import iaik.cms.SecurityProvider;
import iaik.cms.SignedData;
import iaik.cms.SignedDataStream;
import iaik.cms.SignerInfo;
import iaik.cms.SubjectKeyID;
import iaik.cms.attributes.CMSContentType;
import iaik.cms.attributes.SigningTime;
import iaik.pkcs.pkcs1.MGF1ParameterSpec;
import iaik.pkcs.pkcs1.MaskGenerationAlgorithm;
import iaik.pkcs.pkcs1.RSAPssParameterSpec;
import iaik.utils.Util;
import iaik.x509.X509Certificate;
import iaik.x509.X509ExtensionException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.spec.InvalidParameterSpecException;

import demo.DemoUtil;
import demo.keystore.CMSKeyStore;

/**
 * This class demonstrates the CMS SignedData implementation for
 * the RSA-PSS (PKCS#1v2.1) algorithm.
 * 
 * @author Dieter Bratko
 */
public class PssSignedDataDemo {

  // certificate of user 1
  X509Certificate user1;
  // private key of user 1
  PrivateKey user1_pk;
  // certificate of user 2
  X509Certificate user2;
  // private key of user 2
  PrivateKey user2_pk;
 
  // a certificate chain containing the user certs + CA
  Certificate[] certificates;
  Certificate[] certs;
  Certificate[] user1Certs;
  
  // just for attribute certificate testing
  PrivateKey issuer1_pk;

  /**
   * Setups the demo certificate chains.
   * 
   * Keys and certificate are retrieved from the demo KeyStore.
   * 
   * @exception IOException if an file read error occurs
   */
  public PssSignedDataDemo() throws IOException {
    
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                             PssSignedDataDemo                                  *");
    System.out.println("* (shows the usage of the CMS SignedData type with the RSA PSS signature scheme) *");
    System.out.println("**********************************************************************************");
    System.out.println();
    
    // add all certificates to the list
    user1Certs = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    user1 = (X509Certificate)user1Certs[0];
    user1_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    user2 = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_2048_SIGN)[0];
    user2_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_2048_SIGN);
      
    certs = user1Certs;
    certificates = new Certificate[certs.length+1];
    System.arraycopy(certs, 0, certificates, 0, certs.length);
    certificates[certs.length] = user2;
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
    
    System.out.print("Create a new message signed by user 1 :");
   
    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);
    // create a new SignedData object which includes the data
    SignedDataStream signed_data = new SignedDataStream(is, mode);
    
    // SignedData shall include the certificate chain for verifying
    signed_data.setCertificates(certificates);
    
    // cert at index 0 is the user certificate
    IssuerAndSerialNumber issuer = new IssuerAndSerialNumber(user1);

    // create a new SignerInfo for RSA-PSS with default parameters
    SignerInfo signer_info = new SignerInfo(issuer, 
                                            (AlgorithmID)AlgorithmID.sha1.clone(),
                                            (AlgorithmID)AlgorithmID.rsassaPss.clone(),
                                            user1_pk);
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
      // another SignerInfo without signed attributes and RSA-PSS with user defined parameters
      AlgorithmID hashID = (AlgorithmID)AlgorithmID.sha512.clone();
      AlgorithmID mgfID = (AlgorithmID)AlgorithmID.mgf1.clone();
      int saltLength = 64;
      AlgorithmID rsaPssID = null;
      try {
        rsaPssID = createPssAlgorithmID(hashID, mgfID, saltLength);
      } catch (Exception ex) {
        throw new CMSException("Error creating PSS parameters: " + ex.toString());
      }   
      signer_info = new SignerInfo(new SubjectKeyID(user2), 
                                   hashID, 
                                   rsaPssID,
                                   user2_pk);
      
      // the message digest itself is protected
      signed_data.addSignerInfo(signer_info);

    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("No implementation for signature algorithm: "+ex.getMessage());
    } catch (X509ExtensionException ex) {
      throw new CMSException("Cannot create SubjectKeyID for user2 : " + ex.getMessage());
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
   * @param message the message which was transmitted out-of-band (if explicit signed),
   *                otherwise <code>null</code> (implicit signed)
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
      // explicitly signed; set the data stream for digesting the message
      signed_data.setInputStream(new ByteArrayInputStream(message));
    }

    // get an InputStream for reading the signed content
    InputStream data = signed_data.getInputStream();
    ByteArrayOutputStream os = new ByteArrayOutputStream();
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
        System.out.println("Signature ERROR from signer: "+signed_data.getCertificate(signer_infos[i].getSignerIdentifier()).getSubjectDN());
        throw new CMSException(ex.toString());
      } 
    }  
    
    // now check alternative signature verification
    System.out.println("Now check the signature assuming that no certs have been included:");
    try {
       SignerInfo signer_info = signed_data.verify(user1);
        // if the signature is OK the certificate of the signer is returned
        System.out.println("Signature OK from signer: "+user1.getSubjectDN());
        
    } catch (SignatureException ex) {
        // if the signature is not OK a SignatureException is thrown
        System.out.println("Signature ERROR from signer: "+user1.getSubjectDN());
        throw new CMSException(ex.toString());
    }
  
  
    try {
      SignerInfo signer_info = signed_data.verify(user2);
      // if the signature is OK the certificate of the signer is returned
      System.out.println("Signature OK from signer: "+signed_data.getCertificate(signer_info.getSignerIdentifier()).getSubjectDN());
        
    } catch (SignatureException ex) {
      // if the signature is not OK a SignatureException is thrown
      System.out.println("Signature ERROR from signer: "+user2.getSubjectDN());
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
    
    System.out.println("Create a new message signed by user 1 :");
  
    // create a new SignedData object which includes the data
    SignedData signed_data = new SignedData(message, mode);
    
    // SignedData shall include the certificate chain for verifying
    signed_data.setCertificates(certificates);
  
    // cert at index 0 is the user certificate
    IssuerAndSerialNumber issuer = new IssuerAndSerialNumber(user1);

    // create a new SignerInfo for RSA-PSS with default parameters
    SignerInfo signer_info = new SignerInfo(issuer, 
                                            (AlgorithmID)AlgorithmID.sha1.clone(),
                                            (AlgorithmID)AlgorithmID.rsassaPss.clone(),
                                            user1_pk);
    
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

      // another SignerInfo without signed attributes and RSA-PSS with user defined parameters
      AlgorithmID hashID = (AlgorithmID)AlgorithmID.sha512.clone();
      AlgorithmID mgfID = (AlgorithmID)AlgorithmID.mgf1.clone();
      int saltLength = 64;
      AlgorithmID rsaPssID = null;
      try {
        rsaPssID = createPssAlgorithmID(hashID, mgfID, saltLength);
      } catch (Exception ex) {
        throw new CMSException("Error creating PSS parameters: " + ex.toString());
      }   
      signer_info = new SignerInfo(new SubjectKeyID(user2), 
                                   hashID, 
                                   rsaPssID,
                                   user2_pk);
  
      signed_data.addSignerInfo(signer_info);

    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("No implementation for signature algorithm: "+ex.getMessage());
    } catch (X509ExtensionException ex) {
      throw new CMSException("Cannot create SubjectKeyID for user2 : " + ex.getMessage());
    }     
    return signed_data.getEncoded();
  }
  
  
  /**
   * Parses a CMS <code>SignedData</code> object and verifies the signatures
   * for all participated signers.
   *
   * @param encoding the DER encoded <code>SignedData</code> object
   * @param message the message which was transmitted out-of-band (if explicit signed),
   *                otherwise <code>null</code> (implicit signed)
   *
   * @return the inherent message as byte array
   * @exception CMSException if any signature does not verify
   * @exception IOException if some stream I/O error occurs
   */
  public byte[] getSignedData(byte[] encoding, byte[] message) throws CMSException, IOException {
    
    // create the SignedData object
    SignedData signed_data = new SignedData(new ByteArrayInputStream(encoding));
    if (signed_data.getMode() == SignedData.EXPLICIT) {
      // explicitly signed; set the data stream for digesting the message
      signed_data.setContent(message);
    }
   
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
         System.out.println("Signature ERROR from signer: "+signed_data.getCertificate(signer_infos[i].getSignerIdentifier()).getSubjectDN());
         throw new CMSException(ex.toString());
      } 
    }      
    
    // now check alternative signature verification
    System.out.println("Now check the signature assuming that no certs have been included:");
    try {
      SignerInfo signer_info = signed_data.verify(user1);
      // if the signature is OK the certificate of the signer is returned
      System.out.println("Signature OK from signer: "+signed_data.getCertificate(signer_info.getSignerIdentifier()).getSubjectDN());
        
    } catch (SignatureException ex) {
      // if the signature is not OK a SignatureException is thrown
      System.out.println("Signature ERROR from signer: "+user1.getSubjectDN());
      throw new CMSException(ex.toString());
    }
    try {
      SignerInfo signer_info = signed_data.verify(user2);
      // if the signature is OK the certificate of the signer is returned
      System.out.println("Signature OK from signer: "+signed_data.getCertificate(signer_info.getSignerIdentifier()).getSubjectDN());
        
    } catch (SignatureException ex) {
      // if the signature is not OK a SignatureException is thrown
      System.out.println("Signature ERROR from signer: "+user2.getSubjectDN());
      throw new CMSException(ex.toString());
    }    
    return signed_data.getContent();
  }
  
  /**
   * Creates a RSA-PSS AlgorithmID with the supplied parameters (hash algorithm id,
   * mask generation function, salt length).
   *
   * @param hashID the hash algorithm to be used
   * @param mgfID the mask generation function to be used
   * @param saltLength the salt length to be used
   *
   * @return the RSA-PSS algorithm id with the given parameters 
   *
   * @exception InvalidAlgorithmParameterException if the parameters cannot be created/set
   * @exception NoSuchAlgorithmException if there is no AlgorithmParameters implementation
   *                                     for RSA-PSS
   */
  public AlgorithmID createPssAlgorithmID(AlgorithmID hashID, AlgorithmID mgfID, int saltLength)
    throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        
    AlgorithmID rsaPssID = (AlgorithmID)AlgorithmID.rsassaPss.clone();
    mgfID.setParameter(hashID.toASN1Object());
    // create a RSAPssParameterSpec
    RSAPssParameterSpec pssParamSpec = new RSAPssParameterSpec(hashID, mgfID, saltLength);
    // optionally set hash and mgf engines
    MessageDigest hashEngine = hashID.getMessageDigestInstance("IAIK");
    pssParamSpec.setHashEngine(hashEngine);
    MaskGenerationAlgorithm mgfEngine = mgfID.getMaskGenerationAlgorithmInstance("IAIK");
    MGF1ParameterSpec mgf1Spec = new MGF1ParameterSpec(hashID);
    mgf1Spec.setHashEngine(hashEngine);
    mgfEngine.setParameters(mgf1Spec);
    pssParamSpec.setMGFEngine(mgfEngine);

    AlgorithmParameters pssParams = null;
    try {
      pssParams = AlgorithmParameters.getInstance(SecurityProvider.IMPLEMENTATION_NAME_RSA_PSS, "IAIK");
      pssParams.init(pssParamSpec);
    } catch (NoSuchProviderException ex) {
      throw new NoSuchAlgorithmException("RSA-PSS implementation of provider IAIK not available!");  
    } catch (InvalidParameterSpecException ex) {
      throw new InvalidAlgorithmParameterException("Cannot init PSS params: " + ex.getMessage());  
    }    
   
    rsaPssID.setAlgorithmParameters(pssParams);
    return rsaPssID;
  }  

  /**
   * Tests the CMS SignedData implementation for
   * the RSA-PSS (PKCS#1v2.1) algorithm.
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
      System.out.println("Stream implementation demos (RSA-PPS signing)");
      System.out.println("=============================================");
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
      System.out.println("\nNon-stream implementation demos (RSA-PPS signing)");
      System.out.println("===================================================");
   
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
   */
  public static void main(String argv[]) throws Exception {

   	DemoUtil.initDemos();
    (new PssSignedDataDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}