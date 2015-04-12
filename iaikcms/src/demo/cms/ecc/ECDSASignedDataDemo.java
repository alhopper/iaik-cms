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
// $Header: /IAIK-CMS/current/src/demo/cms/ecc/ECDSASignedDataDemo.java 27    3.07.12 13:37 Dbratko $
// $Revision: 27 $
//

package demo.cms.ecc;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.cms.CMSAlgorithmID;
import iaik.cms.CMSException;
import iaik.cms.ContentInfo;
import iaik.cms.ContentInfoStream;
import iaik.cms.IssuerAndSerialNumber;
import iaik.cms.SignedData;
import iaik.cms.SignedDataStream;
import iaik.cms.SignerInfo;
import iaik.cms.attributes.CMSContentType;
import iaik.cms.attributes.SigningTime;
import iaik.utils.KeyAndCertificate;
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
import demo.cms.ecc.keystore.CMSEccKeyStore;


/**
 * This class demonstrates the IAIK-CMS SignedData(Stream) implementation
 * with the ECDSA (with SHA1, SHA224, SHA256, SHA384, SHA512, RIPEMD160) signature algorithm. 
 * <p>
 * Any keys/certificates required for this demo are read from a keystore
 * file "cmsecc.keystore" located in your current working directory. If
 * the keystore file does not exist you can create it by running the
 * {@link demo.cms.ecc.keystore.SetupCMSEccKeyStore SetupCMSEccKeyStore}
 * program. 
 * <br>
 * Additaionally to <code>iaik_cms.jar</code> you also must have 
 * <code>iaik_jce_(full).jar</code> (IAIK-JCE, <a href =
 * "http://jce.iaik.tugraz.at/sic/products/core_crypto_toolkits/jca_jce">
 * http://jce.iaik.tugraz.at/sic/products/core_crypto_toolkits/jca_jce</a>)
 * and <code>iaik_ecc.jar</code> (IAIK-ECC, <a href =
 * "http://jce.iaik.tugraz.at/sic/products/core_crypto_toolkits/ecc">
 * http://jce.iaik.tugraz.at/sic/products/core_crypto_toolkits/ecc</a>)
 * in your classpath.
 * 
 * @author Dieter Bratko
 */
public class ECDSASignedDataDemo {

  /**
   * Default Constructor.
   */
  public ECDSASignedDataDemo() throws Exception {
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                           ECDSASignedData demo                                 *");
    System.out.println("*      (shows how to use the SignedData(Stream) implementation with ECDSA)       *");
    System.out.println("**********************************************************************************");
    System.out.println();
    
  }
  
  /**
   * Creates an ECDSA signed CMS <code>SignedDataStream</code> object and wraps it by a
   * CMS <code>ContentInfoStream</code>.
   *
   * @param message the message to be signed, as byte representation
   * @param mode the transmission mode, either IMPLICIT or EXPLICIT
   * @param hashAlgorithm the hash algorithm to be used
   * @param signatureAlgorithm the signature algorithm to be used
   * @param signerKey the private key of the signer
   * @param certificates the certificate chain of the signer
   * 
   * @return the DER encoding of the <code>ContentInfo</code> object just created
   * 
   * @exception CMSException if the <code>SignedData</code>, <codeContentInfo</code>
   *            object cannot be created
   * @exception IOException if an I/O related error occurs
   */
  public byte[] createSignedDataStream(byte[] message, 
                                       int mode,
                                       AlgorithmID hashAlgorithm,
                                       AlgorithmID signatureAlgorithm,
                                       PrivateKey signerKey,
                                       X509Certificate[] certificates) 
    throws CMSException, IOException  {
    
    System.out.print("Create a new message signed with " + signatureAlgorithm.getName());
   
    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);
    // create a new SignedData object which includes the data
    SignedDataStream signed_data = new SignedDataStream(is, mode);
    
    // SignedData shall include the certificate chain for verifying
    signed_data.setCertificates(certificates);

    // cert at index 0 is the user certificate
    IssuerAndSerialNumber issuer = new IssuerAndSerialNumber(certificates[0]);

    // create a new SignerInfo
    AlgorithmID ecdsaSig = (AlgorithmID)signatureAlgorithm.clone();
    // CMS-ECDSA requires to encode the parameter field as NULL (see RFC 3278)
    ecdsaSig.encodeAbsentParametersAsNull(true);
    SignerInfo signer_info = new SignerInfo(issuer, (AlgorithmID)hashAlgorithm.clone(), ecdsaSig, signerKey);
    
    try {
      // create some signed attributes
      // the message digest attribute is automatically added
      Attribute[] attributes = new Attribute[2];
      // content type is data
      CMSContentType contentType = new CMSContentType(ObjectID.cms_data);
      attributes[0] = new Attribute(contentType);
      // signing time is now
      SigningTime signingTime = new SigningTime();
      attributes[1] = new Attribute(signingTime);
  
      // set the attributes
      signer_info.setSignedAttributes(attributes);
    } catch (Exception ex) {
      throw new CMSException("Error adding attributes: " + ex.toString());
    }
    
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
      while ((r = data_is.read(buf)) > 0) {
        ;   // skip data
      }  
    }

    signed_data.setBlockSize(2048);
     // create the ContentInfo
    ContentInfoStream cis = new ContentInfoStream(signed_data);
    // return the SignedData as DER encoded byte array with block size 2048
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    cis.writeTo(os);
    return os.toByteArray();
  }
  
  
  /**
   * Parses a CMS <code>ContentInfo</code> object holding a <code>SignedData</code> 
   * object and verifies the signature.
   *
   * @param signedData the <code>ContentInfo</code> holding the <code>SignedData</code> 
   *                   object as BER encoded byte array
   * @param message the the message which was transmitted out-of-band (explicit signed)
   * @param certificates the certificate of the signer (used for alternative signature verification)
   * 
   * @return the inherent message as byte array
   * 
   * @exception CMSException if any signature does not verify
   * @exception IOException if an I/O related error occurs
   */
  public byte[] getSignedDataStream(byte[] signedData, byte[] message, X509Certificate[] certificates) 
    throws CMSException, IOException {

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(signedData);

    SignedDataStream signed_data = new SignedDataStream(is);

    if (signed_data.getMode() == SignedDataStream.EXPLICIT) {
      // in explicit mode explicitly supply the content for hash computation
      signed_data.setInputStream(new ByteArrayInputStream(message));
    }

    // get an InputStream for reading the signed content and update hash computation
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
        // check for some included attributes
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
      SignerInfo signer_info = signed_data.verify(certificates[0]);
      // if the signature is OK the certificate of the signer is returned
      System.out.println("Signature OK from signer: "+signed_data.getCertificate(signer_info.getSignerIdentifier()).getSubjectDN());
    } catch (SignatureException ex) {
      // if the signature is not OK a SignatureException is thrown
      System.out.println("Signature ERROR from signer: "+certificates[0].getSubjectDN());
      throw new CMSException(ex.toString());
    }
    return os.toByteArray();
  }
  
  
  /**
   * Creates an ECDSA signed CMS <code>SignedData</code> object and wraps it by a CMS
   * <code>ContentInfo</code> object.
   * <p>
   *
   * @param message the message to be signed, as byte representation
   * @param mode the mode, either SignedData.IMPLICIT or SignedData.EXPLICIT
   * @param hashAlgorithm the hash algorithm to be used
   * @param signatureAlgorithm the signature algorithm to be used
   * @param signerKey the private key of the signer
   * @param certificates the certificate chain of the signer
   * 
   * @return the DER encoded <code>SignedData</code>-<code>ContentInfo</code> object
   *  
   * @exception CMSException if the <code>SignedData</code>-<code>ContentInfo</code> object cannot
   *                          be created
   * @exception IOException if an I/O related error occurs
   */
  public byte[] createSignedData(byte[] message, 
                                 int mode,
                                 AlgorithmID hashAlgorithm,
                                 AlgorithmID signatureAlgorithm,
                                 PrivateKey signerKey,
                                 X509Certificate[] certificates) 
    throws CMSException, IOException  {
    
    System.out.println("Create a new message signed with " + signatureAlgorithm.getName());
  
    // create a new SignedData object which includes the data
    SignedData signed_data = new SignedData(message, mode);
    
    // SignedData shall include the certificate chain for verifying
    signed_data.setCertificates(certificates);
  
    // cert at index 0 is the user certificate
    IssuerAndSerialNumber issuer = new IssuerAndSerialNumber(certificates[0]);

    // create a new SignerInfo
    AlgorithmID ecdsaSig = (AlgorithmID)signatureAlgorithm.clone();
    // CMS-ECC requires that the parameters field is encoded as ASN.1 NULL object (see RFC 3278)
    ecdsaSig.encodeAbsentParametersAsNull(true);
    SignerInfo signer_info = new SignerInfo(issuer, (AlgorithmID)hashAlgorithm.clone(), ecdsaSig, signerKey);
    
    try {
      // create some signed attributes
      // the message digest attribute is automatically added
      Attribute[] attributes = new Attribute[2];
      // content type is data
      CMSContentType contentType = new CMSContentType(ObjectID.cms_data);
      attributes[0] = new Attribute(contentType);
      // signing time is now
      SigningTime signingTime = new SigningTime();
      attributes[1] = new Attribute(signingTime);
  
      // set the attributes
      signer_info.setSignedAttributes(attributes);
    } catch (Exception ex) {
      throw new CMSException("Error adding attributes: " + ex.toString());
    }
    
    // finish the creation of SignerInfo by calling method addSigner
    try {
      signed_data.addSignerInfo(signer_info);
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("No implementation for signature algorithm: "+ex.getMessage());
    }

    ContentInfo ci = new ContentInfo(signed_data); 
    return ci.getEncoded();
  }
  
  
  /**
   * Parses a CMS <code>ContentInfo</code> holding a <code>SignedData</code> 
   * object and verifies the signature.
   *
   * @param signedData the <code>ContentInfo</code> holding the <code>SignedData</code> 
   *                   object as DER encoded byte array
   * @param message the message which was transmitted out-of-band (explicit signed)
   * @param certificates the certificate of the signer (used for alternative signature verification) 
   * 
   * @return the inherent message as byte array
   * 
   * @exception CMSException if any signature does not verify
   * @exception IOException if an I/O related error occurs
   */
  public byte[] getSignedData(byte[] signedData, byte[] message, X509Certificate[] certificates) 
    throws CMSException, IOException {
    
    ByteArrayInputStream is = new ByteArrayInputStream(signedData);
    // create the SignedData object
    SignedData signed_data = new SignedData(is);
    
    if (signed_data.getMode() == SignedData.EXPLICIT) {
      // in explcit mode explictly supply the content data to do the hash calculation
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
        // check some attributes
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
      SignerInfo signer_info = signed_data.verify(certificates[0]);
      // if the signature is OK the certificate of the signer is returned
      System.out.println("Signature OK from signer: "+signed_data.getCertificate(signer_info.getSignerIdentifier()).getSubjectDN());
    } catch (SignatureException ex) {
      // if the signature is not OK a SignatureException is thrown
      System.out.println("Signature ERROR from signer: "+certificates[0].getSubjectDN());
      throw new CMSException(ex.toString());
    }
    return signed_data.getContent();
  }

  /**
   * Runs the signing - verifying demo.
   * 
   * @param message the message to be signed
   * @param hashAlgorithm the hash algorithm to be used
   * @param signatureAlgorithm the signature algorithm to be used
   * @param signerKeyAndCert private key and certificate chain of the signer
   */
  public void runDemo(byte[] message, 
                      AlgorithmID hashAlgorithm,
                      AlgorithmID signatureAlgorithm,
                      KeyAndCertificate signerKeyAndCert) 
    throws Exception {
    
    PrivateKey signerKey = signerKeyAndCert.getPrivateKey();
    X509Certificate[] signerCerts = signerKeyAndCert.getCertificateChain();
    
    byte[] encodedSignedData;
    byte[] received_message = null;
    
    System.out.println("\nRun demos for " + hashAlgorithm.getName() + " / " + signatureAlgorithm.getName() + "\n");
      
    System.out.println("Stream implementation demos");
    System.out.println("===========================");
    //
    // test CMS Implicit SignedDataStream
    //
    System.out.println("\nImplicit SignedDataStream demo [create]:\n");
    encodedSignedData = createSignedDataStream(message, 
                                               SignedDataStream.IMPLICIT,
                                               hashAlgorithm,
                                               signatureAlgorithm,
                                               signerKey,
                                               signerCerts);
    System.out.println();
   
    // transmit data
    System.out.println("\nImplicit SignedDataStream demo [parse]:\n");
    received_message = getSignedDataStream(encodedSignedData, null, signerCerts);
    System.out.print("\nSigned content: ");
    System.out.println(new String(received_message));
      
    //
    // test CMS Explicit SignedDataStream
    //
    System.out.println("\nExplicit SignedDataStream demo [create]:\n");
    encodedSignedData = createSignedDataStream(message,
                                               SignedDataStream.EXPLICIT,
                                               hashAlgorithm,
                                               signatureAlgorithm,
                                               signerKey,
                                               signerCerts);
    // transmit data
    System.out.println("\nExplicit SignedDataStream demo [parse]:\n");
    received_message = getSignedDataStream(encodedSignedData, message, signerCerts);
    System.out.print("\nSigned content: ");
    System.out.println(new String(received_message));
      
    // the non-stream implementation
    System.out.println("\nNon-stream implementation demos");
    System.out.println("===============================");

    //
    // test CMS Implicit SignedData
    //
    System.out.println("\nImplicit CMS SignedData demo [create]:\n");
    encodedSignedData = createSignedData(message, 
                                         SignedData.IMPLICIT,
                                         hashAlgorithm,
                                         signatureAlgorithm,
                                         signerKey,
                                         signerCerts);
    // transmit data
    System.out.println("\nImplicit CMS SignedData demo [parse]:\n");
    received_message = getSignedData(encodedSignedData, null, signerCerts);
    System.out.print("\nSigned content: ");
    System.out.println(new String(received_message));

    //
    // test CMS Explicit SignedData
    //
    System.out.println("\nExplicit CMS SignedData demo [create]:\n");
    encodedSignedData = createSignedData(message, 
                                         SignedData.EXPLICIT,
                                         hashAlgorithm,
                                         signatureAlgorithm,
                                         signerKey,
                                         signerCerts);
    // transmit data
    System.out.println("\nExplicit CMS SignedData demo [parse]:\n");
    received_message = getSignedData(encodedSignedData, message, signerCerts);
    System.out.print("\nSigned content: ");
    System.out.println(new String(received_message));
   	
  }
  
  /**
   * Tests the CMS SignedData implementation with the ECDSA signature
   * algorithm and several hash algorithms.
   */
  public void start() throws Exception {
    // add ECC provider    
    ECCDemoUtil.installIaikEccProvider();
     // the test message
    String m = "This is the test message.";
    System.out.println("Test message: \""+m+"\"");
    System.out.println();
    byte[] message = m.getBytes();

    AlgorithmID[][] algorithms = new AlgorithmID[][] {
                                   { CMSAlgorithmID.sha1, CMSAlgorithmID.ecdsa_With_SHA1 },
                                   { CMSAlgorithmID.sha224, CMSAlgorithmID.ecdsa_With_SHA224 },
                                   { CMSAlgorithmID.sha256, CMSAlgorithmID.ecdsa_With_SHA256 },
                                   { CMSAlgorithmID.sha384, CMSAlgorithmID.ecdsa_With_SHA384 },
                                   { CMSAlgorithmID.sha512, CMSAlgorithmID.ecdsa_With_SHA512 },
                                   // ECDSA with RIPEMD-160 in plain format (BSI)
                                   { CMSAlgorithmID.ripeMd160, CMSAlgorithmID.ecdsa_plain_With_RIPEMD160 },
                                 };

    // get signer key and certs                                 
    KeyAndCertificate[] keyAndCerts = {
      // P-192  
      new KeyAndCertificate(CMSEccKeyStore.getPrivateKey(CMSEccKeyStore.ECDSA, CMSEccKeyStore.SZ_192_SIGN),
                            CMSEccKeyStore.getCertificateChain(CMSEccKeyStore.ECDSA, CMSEccKeyStore.SZ_192_SIGN)),
      // P-224  
      new KeyAndCertificate(CMSEccKeyStore.getPrivateKey(CMSEccKeyStore.ECDSA, CMSEccKeyStore.SZ_224_SIGN),
                            CMSEccKeyStore.getCertificateChain(CMSEccKeyStore.ECDSA, CMSEccKeyStore.SZ_224_SIGN)),
      // P-256  
      new KeyAndCertificate(CMSEccKeyStore.getPrivateKey(CMSEccKeyStore.ECDSA, CMSEccKeyStore.SZ_256_SIGN),
                            CMSEccKeyStore.getCertificateChain(CMSEccKeyStore.ECDSA, CMSEccKeyStore.SZ_256_SIGN)),
      // P-384                      
      new KeyAndCertificate(CMSEccKeyStore.getPrivateKey(CMSEccKeyStore.ECDSA, CMSEccKeyStore.SZ_384_SIGN),
                            CMSEccKeyStore.getCertificateChain(CMSEccKeyStore.ECDSA, CMSEccKeyStore.SZ_384_SIGN)),
      // P-521                            
      new KeyAndCertificate(CMSEccKeyStore.getPrivateKey(CMSEccKeyStore.ECDSA, CMSEccKeyStore.SZ_521_SIGN),
                            CMSEccKeyStore.getCertificateChain(CMSEccKeyStore.ECDSA, CMSEccKeyStore.SZ_521_SIGN)),                                    
      // P-192 (for ECDSA with RIPEMD-160 in plain format (BSI)  
      new KeyAndCertificate(CMSEccKeyStore.getPrivateKey(CMSEccKeyStore.ECDSA, CMSEccKeyStore.SZ_192_SIGN),
                            CMSEccKeyStore.getCertificateChain(CMSEccKeyStore.ECDSA, CMSEccKeyStore.SZ_192_SIGN)),
                            
                             
    };
                                 
    final int HASH_ALG = 0;
    final int SIGNATURE_ALG = 1;
    for (int i = 0; i < algorithms.length; i++) {
      runDemo(message, algorithms[i][HASH_ALG], algorithms[i][SIGNATURE_ALG], keyAndCerts[i]);
    }
   
  }  
  
  /**
   * Starts the demo.
   * 
   * @exception Exception 
   *            if an error occurs 
   */
  public static void main(String argv[]) throws Exception {

    DemoUtil.initDemos();
    ECCDemoUtil.installIaikEccProvider();   
    (new ECDSASignedDataDemo()).start();
    System.out.println("\nReady!");
    System.in.read();
  }
    
}