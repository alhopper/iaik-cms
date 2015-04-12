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
// $Header: /IAIK-CMS/current/src/demo/cms/pkcs7cms/PKCS7CMSSignedDataDemo.java 20    23.08.13 14:27 Dbratko $
// $Revision: 20 $
//

package demo.cms.pkcs7cms;

import iaik.asn1.ASN1Object;
import iaik.asn1.CodingException;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.asn1.structures.ChoiceOfTime;
import iaik.asn1.structures.PolicyInformation;
import iaik.asn1.structures.PolicyQualifierInfo;
import iaik.cms.CMSException;
import iaik.cms.IssuerAndSerialNumber;
import iaik.cms.SignedData;
import iaik.cms.SignedDataStream;
import iaik.cms.SignerInfo;
import iaik.cms.Utils;
import iaik.pkcs.PKCSException;
import iaik.smime.ess.SigningCertificate;
import iaik.utils.CryptoUtils;
import iaik.utils.Util;
import iaik.x509.X509Certificate;
import iaik.x509.attr.AttributeCertificate;

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
 * This class demonstrates the CMS SignedData implementation and checks it
 * against the IAIK PKCS#7 library.
 * 
 * @author Dieter Bratko
 */
public class PKCS7CMSSignedDataDemo {

  // certificate of user 1
  X509Certificate user1Cert_;
  // private key of user 1
  PrivateKey user1PrivKey_;
  // certificate of user 2
  X509Certificate user2Cert_;
  // private key of user 2
  PrivateKey user2PrivKey_;
  // a certificate array containing the user certs + CA
  X509Certificate[] certificates_;
  // certificates of user1
  X509Certificate[] user1Certs_;
  

  /**
   * Setup the demo certificate chains.
   * 
   * Keys and certificate are retrieved from the demo KeyStore.
   * 
   * @exception IOException if an file read error occurs
   */
  public PKCS7CMSSignedDataDemo() throws IOException {
    
    System.out.println();
    System.out.println("***********************************************************************************************");
    System.out.println("*                                 PKCS7CMSSignedDataDemo                                      *");
    System.out.println("*    (tests the CMS SignedData against the IAIK-JCE PKCS#7 Signedata type implementation)     *");
    System.out.println("***********************************************************************************************");
    System.out.println();
    
    // add all certificates to the list
    user1Certs_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    user1Cert_ = (X509Certificate)user1Certs_[0];
    user1PrivKey_ = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    user2Cert_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_2048_SIGN)[0];
    user2PrivKey_ = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_2048_SIGN);
    
    certificates_ = new X509Certificate[user1Certs_.length + 1];
    System.arraycopy(user1Certs_, 0, certificates_, 0, user1Certs_.length);
    certificates_[user1Certs_.length] = user2Cert_;
    
  }
  
    
  
  /**
   * Creates a CMS <code>SignedData</code> object.
   * <p>
   *
   * @param message the message to be signed, as byte representation
   * @param mode the transmission mode, either IMPLICIT or EXPLICIT
   * 
   * @return the DER encoding of the <code>SignedData</code> object just created
   * @exception CMSException if the <code>SignedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createSignedDataStream(byte[] message, int mode) throws CMSException, IOException  {
    
    System.out.print("Create a new message signed by user 1 :");
   
    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);
    // create a new SignedData object which includes the data
    SignedDataStream signed_data = new SignedDataStream(is, mode);
    
    // SignedData shall include the certificate chain for verifying
    signed_data.setCertificates(certificates_);
    
    // cert at index 0 is the user certificate
    IssuerAndSerialNumber issuer = new IssuerAndSerialNumber(user1Cert_);

    // create a new SignerInfo
    SignerInfo signer_info = new SignerInfo(issuer, (AlgorithmID)AlgorithmID.sha1.clone(), user1PrivKey_);
    // create some authenticated attributes
    // the message digest attribute is automatically added
    Attribute[] attributes = new Attribute[3];
    // content type is data
    attributes[0] = new Attribute(ObjectID.contentType, new ASN1Object[] {ObjectID.pkcs7_data});
    // signing time is now
    attributes[1] = new Attribute(ObjectID.signingTime, new ASN1Object[] {new ChoiceOfTime().toASN1Object()});
    // signing certificate
    try {
      SigningCertificate signingCertificate = new SigningCertificate(user1Certs_, true);
      String explicitText = "This certificate only may be used for test purposes";
      PolicyQualifierInfo policyQualifier = new PolicyQualifierInfo(null, null, explicitText);
      PolicyInformation[] policyInformations = 
        { new PolicyInformation(new ObjectID("1.3.6.1.4.1.2706.17.0.11.1.1"),
                              new PolicyQualifierInfo[] { policyQualifier }) };
      signingCertificate.setPolicies(policyInformations);                        
      System.out.println("Include signingCertificate attribute:");
      System.out.println(signingCertificate);
      attributes[2] = new Attribute(ObjectID.signingCertificate, new ASN1Object[] {signingCertificate.toASN1Object()});
    } catch (Exception ex) {
      throw new CMSException("Cannot create SigningCertificate attribute: " + ex.getMessage());   
    }    
    // set the attributes
    signer_info.setSignedAttributes(attributes);
    // finish the creation of SignerInfo by calling method addSigner
    try {
      signed_data.addSignerInfo(signer_info);
      // another SignerInfo without signed attributes and RipeMd 160 as hash algorithm
      signer_info = new SignerInfo(new IssuerAndSerialNumber(user2Cert_), 
          (AlgorithmID)AlgorithmID.ripeMd160.clone(), user2PrivKey_);
      
      
      // the message digest itself is protected
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
   * Creates a PKCS#7 <code>SignedData</code> object.
   * <p>
   *
   * @param message the message to be signed, as byte representation
   * @param mode the transmission mode, either IMPLICIT or EXPLICIT
   * @return the DER encoding of the <code>SignedData</code> object just created
   * @exception PKCSException if the <code>SignedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createPKCS7SignedDataStream(byte[] message, int mode) throws iaik.pkcs.PKCSException, IOException  {
    
     // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);
    // create a new SignedData object which includes the data
    iaik.pkcs.pkcs7.SignedDataStream signed_data = new iaik.pkcs.pkcs7.SignedDataStream(is, mode);
    // SignedData shall include the certificate chain for verifying
    signed_data.setCertificates(certificates_);
    
    // cert at index 0 is the user certificate
    iaik.pkcs.pkcs7.IssuerAndSerialNumber issuer = new iaik.pkcs.pkcs7.IssuerAndSerialNumber(user1Cert_);

    // create a new SignerInfo
    iaik.pkcs.pkcs7.SignerInfo signer_info = new iaik.pkcs.pkcs7.SignerInfo(issuer, (AlgorithmID)AlgorithmID.sha1.clone(), user1PrivKey_);
    // create some authenticated attributes
    // the message digest attribute is automatically added
    Attribute[] attributes = new Attribute[2];
    // content type is data
    attributes[0] = new Attribute(ObjectID.contentType, new ASN1Object[] {ObjectID.pkcs7_data});
    // signing time is now
    attributes[1] = new Attribute(ObjectID.signingTime, new ASN1Object[] {new ChoiceOfTime().toASN1Object()});
    // set the attributes
    signer_info.setAuthenticatedAttributes(attributes);
    // finish the creation of SignerInfo by calling method addSigner
    try {
      signed_data.addSignerInfo(signer_info);

      // another SignerInfo without authenticated attributes and RIPEMD-160 as hash algorithm
      signer_info = new iaik.pkcs.pkcs7.SignerInfo(new iaik.pkcs.pkcs7.IssuerAndSerialNumber(user2Cert_), 
          (AlgorithmID)AlgorithmID.ripeMd160.clone(), user2PrivKey_);
      // the message digest itself is protected
      signed_data.addSignerInfo(signer_info);

    } catch (NoSuchAlgorithmException ex) {
      throw new iaik.pkcs.PKCSException("No implementation for signature algorithm: "+ex.getMessage());
    }

    // write the data through SignedData to any out-of-band place
    if (mode == iaik.pkcs.pkcs7.SignedDataStream.EXPLICIT) {
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
   * Parses a CMS or PKCS#7 <code>SignedData</code> object and verifies the signatures
   * for all participated signers.
   *
   * @param signedData <code>SignedData</code> object as DER encoded byte array
   * @param message the the message which was transmitted out-of-band (explicit signed)
   *
   * @return the inherent message as byte array
   * @exception CMSException if any signature does not verify
   * @exception IOException if an I/O error occurs
   */
  public byte[] getSignedDataStream(byte[] signedData, byte[] message) throws CMSException, IOException {

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(signedData);
    // create the SignedData object
    SignedDataStream signed_data = null;
    if (message == null) {
      // implicitly signed; read the DER encoded object
      signed_data = new SignedDataStream(is);
    }
    else {
      // explicitly signed; set the data stream for digesting the message
      AlgorithmID[] algIDs = { (AlgorithmID)AlgorithmID.sha1.clone(), (AlgorithmID)AlgorithmID.ripeMd160.clone() };
      signed_data = new SignedDataStream(new ByteArrayInputStream(message), algIDs);
      
    }

    // get an InputStream for reading the signed content
    InputStream data = signed_data.getInputStream();
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    Util.copyStream(data, os, null);
    
    if (message != null) {
      // if explicitly signed read now the DER encoded object
      // an explicit S/MIME signed message also consits of message|signature
      signed_data.decode(is);
    }

    System.out.println("SignedData contains the following signer information:");
    SignerInfo[] signer_infos = signed_data.getSignerInfos();
    
    for (int i=0; i<signer_infos.length; i++) {
        
      try {
        // verify the signed data using the SignerInfo at index i
        X509Certificate signer_cert = signed_data.verify(i);
        // if the signature is OK the certificate of the signer is returned
        System.out.println("Signature OK from signer: "+signer_cert.getSubjectDN());
        Attribute signingTime = signer_infos[i].getSignedAttribute(ObjectID.signingTime);
        if (signingTime != null) {
          ChoiceOfTime cot = new ChoiceOfTime(signingTime.getValue()[0]);
          System.out.println("This message has been signed at " + cot.getDate());
        } 
        Attribute contentType = signer_infos[i].getSignedAttribute(ObjectID.contentType);
        if (contentType != null) {
          System.out.println("The content has PKCS#7 content type " + contentType.getValue()[0]);
        }
        // check SigningCertificate attribute
        try {
          SigningCertificate signingCertificate = signer_infos[i].getSigningCertificateAttribute();
          if (signingCertificate != null) {
            System.out.println("SigningCertificate attribute included!");
            if (!signingCertificate.isSignerCertificate(signer_cert)) {
              throw new CMSException("Cert ERROR!!! The certificate used for signing is not the one " +
                                     "identified by the SignerCertificate attribute!");
            } else {
              System.out.println("SigningCertificate attribute: Signer cert ok!");   
            } 
            // get the authorization certs for this signerInfo
            Certificate[] authCerts = 
               signingCertificate.getAuthorizedCertificates(signed_data.getCertificates());
            if (authCerts != null) {
              System.out.println("SignedData contains the following authorization certs for SignerInfo No " + (i+1) +":");   
              for (int j = 0; j < authCerts.length; j++) {
                if (authCerts[j].getType().equalsIgnoreCase("X.509")) {
                  System.out.println("X.509 public key cert: " + ((X509Certificate)authCerts[j]).getSubjectDN());
                } else {
                  System.out.println("X.509 attribute cert: " + ((AttributeCertificate)authCerts[j]).getHolder());  
                }     
              }  
            } 
            if (signingCertificate.countPolicies() > 0) {
              // get the certs with PolicyInformations according to the SigningCertificate attribute:
              Certificate[] policyCerts = 
                 signingCertificate.getPolicyInformationCerts(signed_data.getCertificates());
              if (policyCerts != null) {
                System.out.println("SignedData contains the following certs corresponding to policy informations of SignerInfo No " + (i+1) +":");   
                for (int j = 0; j < policyCerts.length; j++) {
                  if (policyCerts[j].getType().equalsIgnoreCase("X.509")) {
                    System.out.println("X.509 public key cert: " + ((X509Certificate)policyCerts[j]).getSubjectDN());
                  } else {
                    System.out.println("X.509 attribute cert: " + ((AttributeCertificate)policyCerts[j]).getHolder());  
                  }     
                }  
              }
            }  
          }  
        } catch (NoSuchAlgorithmException ex) {
          throw new CMSException("Cannot check SigningCertificate attribute: Algorithm SHA not implemented!");
        } catch (CMSException ex) {
          throw new CMSException("Error parsing SigningCertificate attribute: " + ex.getMessage());   
        }    
       
      } catch (SignatureException ex) {
        // if the signature is not OK a SignatureException is thrown
        System.out.println("Signature ERROR from signer: "+signed_data.getCertificate(signer_infos[i].getSignerIdentifier()).getSubjectDN());
        throw new CMSException(ex.toString());
      } catch (CodingException ex) {
        throw new CMSException("Attribute decoding error: " + ex.toString()); 
      }  
    }  
    
    // now check alternative signature verification
    System.out.println("Now check the signature assuming that no certs have been included:");
    try {
       SignerInfo signer_info = signed_data.verify(user1Cert_);
        // if the signature is OK the certificate of the signer is returned
        System.out.println("Signature OK from signer: "+user1Cert_.getSubjectDN());
        
    } catch (SignatureException ex) {
        // if the signature is not OK a SignatureException is thrown
        System.out.println("Signature ERROR from signer: "+user1Cert_.getSubjectDN());
        throw new CMSException(ex.toString());
    }
    
    
    try {
       SignerInfo signer_info = signed_data.verify(user2Cert_);
        // if the signature is OK the certificate of the signer is returned
        System.out.println("Signature OK from signer: "+signed_data.getCertificate(signer_info.getSignerIdentifier()).getSubjectDN());
        
    } catch (SignatureException ex) {
        // if the signature is not OK a SignatureException is thrown
        System.out.println("Signature ERROR from signer: "+user2Cert_.getSubjectDN());
        throw new CMSException(ex.toString());
    }    
        
    return os.toByteArray();
  }
  
    
  /**
   * Parses a PKCS#7 <code>SignedData</code> object and verifies the signatures
   * for all participated signers.
   *
   * @param signedData <code>SignedData</code> object as DER encoded byte array
   * @param message the the message which was transmitted out-of-band (explicit signed)
   *
   * @return the inherent message as byte array
   * @exception iaik.pkcs.PKCSException if any signature does not verify
   * @exception IOException if an I/O error occurs
   */
  public byte[] getPKCS7SignedDataStream(byte[] signedData, byte[] message) throws iaik.pkcs.PKCSException, IOException {

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(signedData);
    // create the SignedData object
    iaik.pkcs.pkcs7.SignedDataStream signed_data = null;
    if (message == null) {
      // implicitly signed; read the DER encoded object
      signed_data = new iaik.pkcs.pkcs7.SignedDataStream(is);
    }
    else {
      // explicitly signed; set the data stream for digesting the message
      AlgorithmID[] algIDs = { (AlgorithmID)AlgorithmID.sha1.clone(), (AlgorithmID)AlgorithmID.ripeMd160.clone() };
      signed_data = new iaik.pkcs.pkcs7.SignedDataStream(new ByteArrayInputStream(message), algIDs);
      
    }

    // get an InputStream for reading the signed content
    InputStream data = signed_data.getInputStream();
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    Util.copyStream(data, os, null);
    
    if (message != null) {
      // if explicitly signed read now the DER encoded object
      // an explicit S/MIME signed message also consits of message|signature
      signed_data.decode(is);
    }

    System.out.println("SignedData contains the following signer information:");
    iaik.pkcs.pkcs7.SignerInfo[] signer_infos = signed_data.getSignerInfos();
    
    for (int i=0; i<signer_infos.length; i++) {
      try {
        // verify the signed data using the SignerInfo at index i
        X509Certificate signer_cert = signed_data.verify(i);
        // if the signature is OK the certificate of the signer is returned
        System.out.println("Signature OK from signer: "+signer_cert.getSubjectDN());
        Attribute signingTime = signer_infos[i].getAuthenticatedAttribute(ObjectID.signingTime);
        if (signingTime != null) {
          ChoiceOfTime cot = new ChoiceOfTime(signingTime.getValue()[0]);
          System.out.println("This message has been signed at " + cot.getDate());
        } 
        Attribute contentType = signer_infos[i].getAuthenticatedAttribute(ObjectID.contentType);
        if (contentType != null) {
          System.out.println("The content has PKCS#7 content type " + contentType.getValue()[0]);
        }  
        
      } catch (SignatureException ex) {
        // if the signature is not OK a SignatureException is thrown
        System.out.println("Signature ERROR from signer: "+signed_data.getCertificate(signer_infos[i].getIssuerAndSerialNumber()).getSubjectDN());
        throw new iaik.pkcs.PKCSException(ex.toString());
      } catch (CodingException ex) {
        throw new iaik.pkcs.PKCSException("Attribute decoding error: " + ex.toString()); 
      }  
    }  
    // now check alternative signature verification
    System.out.println("Now check the signature assuming that no certs have been included:");
    try {
       iaik.pkcs.pkcs7.SignerInfo signer_info = signed_data.verify(user1Cert_);
        // if the signature is OK the certificate of the signer is returned
        System.out.println("Signature OK from signer: "+signed_data.getCertificate(signer_info.getIssuerAndSerialNumber()).getSubjectDN());
        
    } catch (SignatureException ex) {
        // if the signature is not OK a SignatureException is thrown
        System.out.println("Signature ERROR from signer: "+user1Cert_.getSubjectDN());
        throw new iaik.pkcs.PKCSException(ex.toString());
    }
       
    try {
       iaik.pkcs.pkcs7.SignerInfo signer_info = signed_data.verify(user2Cert_);
        // if the signature is OK the certificate of the signer is returned
        System.out.println("Signature OK from signer: "+signed_data.getCertificate(signer_info.getIssuerAndSerialNumber()).getSubjectDN());
        
    } catch (SignatureException ex) {
        // if the signature is not OK a SignatureException is thrown
        System.out.println("Signature ERROR from signer: "+user2Cert_.getSubjectDN());
        throw new iaik.pkcs.PKCSException(ex.toString());
    }    
    
    return os.toByteArray();
  }
  
  
  
  /**
   * Creates a CMS <code>SignedData</code> object.
   * <p>
   *
   * @param message the message to be signed, as byte representation
   * @param mode the mode, either SignedData.IMPLICIT or SignedData.EXPLICIT
   * 
   * @return the <code>SignedData</code> object as ASN.1 object
   * @exception CMSException if the <code>SignedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public ASN1Object createSignedData(byte[] message, int mode) throws CMSException, IOException  {
    
    System.out.println("Create a new message signed by user 1 :");
  
    // create a new SignedData object which includes the data
    SignedData signed_data = new SignedData(message, mode);
    
    // SignedData shall include the certificate chain for verifying
    signed_data.setCertificates(certificates_);
       
    // cert at index 0 is the user certificate
    IssuerAndSerialNumber issuer = new IssuerAndSerialNumber(user1Cert_);

    // create a new SignerInfo
    SignerInfo signer_info = new SignerInfo(issuer, (AlgorithmID)AlgorithmID.sha1.clone(), user1PrivKey_);
    // create some authenticated attributes
    // the message digest attribute is automatically added
    Attribute[] attributes = new Attribute[3];
    // content type is data
    attributes[0] = new Attribute(ObjectID.contentType, new ASN1Object[] {ObjectID.pkcs7_data});
    // signing time is now
    attributes[1] = new Attribute(ObjectID.signingTime, new ASN1Object[] {new ChoiceOfTime().toASN1Object()});
    // signing certificate
    SigningCertificate signingCertificate = Utils.makeSigningCertificate(user1Certs_, null, true);
    System.out.println("Include signingCertificate attribute:");
    System.out.println(signingCertificate);
    attributes[2] = new Attribute(ObjectID.signingCertificate, new ASN1Object[] {signingCertificate.toASN1Object()});
    // set the attributes
    signer_info.setSignedAttributes(attributes);
    // finish the creation of SignerInfo by calling method addSigner
    try {
      signed_data.addSignerInfo(signer_info);

      // another SignerInfo without signed attributes and RIPEMD-160 as hash algorithm
      signer_info = new SignerInfo(new IssuerAndSerialNumber(user2Cert_), 
          (AlgorithmID)AlgorithmID.ripeMd160.clone(), user2PrivKey_);
      signed_data.addSignerInfo(signer_info);

    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("No implementation for signature algorithm: "+ex.getMessage());
    }     

    
    return signed_data.toASN1Object();
  }
  
  
  /**
   * Creates a PKCS#7 <code>SignedData</code> object.
   * <p>
   *
   * @param message the message to be signed, as byte representation
   * @param mode the mode, either SignedData.IMPLICIT or SignedData.EXPLICIT
   * @return the <code>SignedData</code> object as ASN.1 object
   * @exception iaik.pkcs.PKCSException if the <code>SignedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public ASN1Object createPKCS7SignedData(byte[] message, int mode) throws iaik.pkcs.PKCSException, IOException  {

    System.out.println("Create a new message signed by user 1 and 2:");
    

    // create a new SignedData object which includes the data
    iaik.pkcs.pkcs7.SignedData signed_data = new iaik.pkcs.pkcs7.SignedData(message, mode);
    // SignedData shall include the certificate chain for verifying
    signed_data.setCertificates(certificates_);
    
    // cert at index 0 is the user certificate
    iaik.pkcs.pkcs7.IssuerAndSerialNumber issuer = new iaik.pkcs.pkcs7.IssuerAndSerialNumber(user1Cert_);

    // create a new SignerInfo
    iaik.pkcs.pkcs7.SignerInfo signer_info = new iaik.pkcs.pkcs7.SignerInfo(issuer, (AlgorithmID)AlgorithmID.sha1.clone(), user1PrivKey_);
    // create some authenticated attributes
    // the message digest attribute is automatically added
    Attribute[] attributes = new Attribute[2];
    // content type is data
    attributes[0] = new Attribute(ObjectID.contentType, new ASN1Object[] {ObjectID.pkcs7_data});
    // signing time is now
    attributes[1] = new Attribute(ObjectID.signingTime, new ASN1Object[] {new ChoiceOfTime().toASN1Object()});
    // set the attributes
    signer_info.setAuthenticatedAttributes(attributes);
    // finish the creation of SignerInfo by calling method addSigner
    try {
      signed_data.addSignerInfo(signer_info);

      // another SignerInfo without authenticated attributes and RIPEMD-160 as hash algorithm
      signer_info = new iaik.pkcs.pkcs7.SignerInfo(new iaik.pkcs.pkcs7.IssuerAndSerialNumber(user2Cert_), 
          (AlgorithmID)AlgorithmID.ripeMd160.clone(), user2PrivKey_);
      // the message digest itself is protected
      signed_data.addSignerInfo(signer_info);

    } catch (NoSuchAlgorithmException ex) {
      throw new iaik.pkcs.PKCSException("No implementation for signature algorithm: "+ex.getMessage());
    }

    
    return signed_data.toASN1Object();
  }


  /**
   * Parses a CMS or PKCS#7 <code>SignedData</code> object and verifies the signatures
   * for all participated signers.
   *
   * @param obj <code>SignedData</code> object in ASN.1 representation
   * @param message the the message which was transmitted out-of-band (explicit signed)
   *
   * @return the inherent message as byte array
   * @exception CMSException if any signature does not verify
   * @exception IOException if an I/O error occurs
   */
  public byte[] getSignedData(ASN1Object obj, byte[] message) throws CMSException, IOException {

    // create the SignedData object
    SignedData signed_data = null;
    if (message == null) {
      // implicitly signed; read the DER encoded object
      signed_data = new SignedData(obj);
    }
    else {
      // explicitly signed; set the data stream for digesting the message
      AlgorithmID[] algIDs = { (AlgorithmID)AlgorithmID.sha1.clone(), (AlgorithmID)AlgorithmID.ripeMd160.clone() };
      try {
         signed_data = new SignedData(message, algIDs);
      } catch (NoSuchAlgorithmException ex) {
         throw new CMSException(ex.getMessage());
      }  
    }

    // get an InputStream for reading the signed content
    InputStream data = signed_data.getInputStream();
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    Util.copyStream(data, os, null);
    
    if (message != null) {
      // if explicitly signed read now the DER encoded object
      // an explicit S/MIME signed message also consits of message|signature
      signed_data.decode(obj);
    }
    
    System.out.println("SignedData contains the following signer information:");
    SignerInfo[] signer_infos = signed_data.getSignerInfos();
    
    for (int i=0; i<signer_infos.length; i++) {
      try {
        // verify the signed data using the SignerInfo at index i
        X509Certificate signer_cert = signed_data.verify(i);
        // if the signature is OK the certificate of the signer is returned
        System.out.println("Signature OK from signer: "+signer_cert.getSubjectDN());
        Attribute signingTime = signer_infos[i].getSignedAttribute(ObjectID.signingTime);
        if (signingTime != null) {
          ChoiceOfTime cot = new ChoiceOfTime(signingTime.getValue()[0]);
          System.out.println("This message has been signed at " + cot.getDate());
        } 
        Attribute contentType = signer_infos[i].getSignedAttribute(ObjectID.contentType);
        if (contentType != null) {
          System.out.println("The content has PKCS#7 content type " + contentType.getValue()[0]);
        }  
        Attribute signingCertificateAttr = signer_infos[i].getSignedAttribute(ObjectID.signingCertificate);
        if (signingCertificateAttr != null) {
          System.out.println("SigningCertificate attribute included in this SignerInfo.");
          SigningCertificate signingCertificate = new SigningCertificate(signingCertificateAttr.getValue()[0]);
          byte[] certHash;
          try {
            certHash = signer_cert.getFingerprint("SHA");
            if (!CryptoUtils.equalsBlock(certHash, signingCertificate.getESSCertIDs()[0].getCertHash())) {
              System.out.println("Cert ERROR!!! The certificate used for signing is not the one " +
                                "identified by the SignerCertificate attribute!");
                                
            } else {
              System.out.println("SigningCertificate cert hash of Signer cert ok!");   
            }    
          } catch (NoSuchAlgorithmException ex) {
            throw new CMSException("Cannot check SigningCertificate: Algorithm SHA not implemented!");
          }  
        }
      } catch (SignatureException ex) {
        // if the signature is not OK a SignatureException is thrown
        System.out.println("Signature ERROR from signer: "+signed_data.getCertificate(signer_infos[i].getSignerIdentifier()).getSubjectDN());
        throw new CMSException(ex.toString());
      } catch (CodingException ex) {
        throw new CMSException("Attribute decoding error: " + ex.toString()); 
      } 
    }      
    
    // now check alternative signature verification
    System.out.println("Now check the signature assuming that no certs have been included:");
    try {
       SignerInfo signer_info = signed_data.verify(user1Cert_);
        // if the signature is OK the certificate of the signer is returned
        System.out.println("Signature OK from signer: "+signed_data.getCertificate(signer_info.getSignerIdentifier()).getSubjectDN());
        
    } catch (SignatureException ex) {
        // if the signature is not OK a SignatureException is thrown
        System.out.println("Signature ERROR from signer: "+user1Cert_.getSubjectDN());
        throw new CMSException(ex.toString());
    }
         
    try {
       SignerInfo signer_info = signed_data.verify(user2Cert_);
        // if the signature is OK the certificate of the signer is returned
        System.out.println("Signature OK from signer: "+signed_data.getCertificate(signer_info.getSignerIdentifier()).getSubjectDN());
        
    } catch (SignatureException ex) {
        // if the signature is not OK a SignatureException is thrown
        System.out.println("Signature ERROR from signer: "+user2Cert_.getSubjectDN());
        throw new CMSException(ex.toString());
    }    
    
    
    return signed_data.getContent();
  }
  
  /**
   * Parses a PKCS#7 <code>SignedData</code> object and verifies the signatures
   * for all participated signers.
   *
   * @param obj <code>SignedData</code> object in ASN.1 representation
   * @param message the the message which was transmitted out-of-band (explicit signed)
   *
   * @return the inherent message as byte array
   * @exception PKCSException if any signature does not verify
   * @exception IOException if an I/O error occurs
   */
  public byte[] getPKCS7SignedData(ASN1Object obj, byte[] message) throws iaik.pkcs.PKCSException, IOException {

    // create the SignedData object
    iaik.pkcs.pkcs7.SignedData signed_data = null;
    if (message == null) {
      // implicitly signed; read the DER encoded object
      signed_data = new iaik.pkcs.pkcs7.SignedData(obj);
    }
    else {
      // explicitly signed; set the data stream for digesting the message
      AlgorithmID[] algIDs = { (AlgorithmID)AlgorithmID.sha1.clone(), (AlgorithmID)AlgorithmID.ripeMd160.clone() };
      try {
         signed_data = new iaik.pkcs.pkcs7.SignedData(message, algIDs);
      } catch (NoSuchAlgorithmException ex) {
         throw new iaik.pkcs.PKCSException(ex.toString());
      }  
    }

    // get an InputStream for reading the signed content
    InputStream data = signed_data.getInputStream();
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    Util.copyStream(data, os, null);

    if (message != null) {
      // if explicitly signed read now the DER encoded object
      // an explicit S/MIME signed message also consits of message|signature
      signed_data.decode(obj);
    }
    
    System.out.println("SignedData contains the following signer information:");
    iaik.pkcs.pkcs7.SignerInfo[] signer_infos = signed_data.getSignerInfos();
    
    for (int i=0; i<signer_infos.length; i++) {
      try {
        // verify the signed data using the SignerInfo at index i
        X509Certificate signer_cert = signed_data.verify(i);
        // if the signature is OK the certificate of the signer is returned
        System.out.println("Signature OK from signer: "+signer_cert.getSubjectDN());
        Attribute signingTime = signer_infos[i].getAuthenticatedAttribute(ObjectID.signingTime);
        if (signingTime != null) {
          ChoiceOfTime cot = new ChoiceOfTime(signingTime.getValue()[0]);
          System.out.println("This message has been signed at " + cot.getDate());
        } 
        Attribute contentType = signer_infos[i].getAuthenticatedAttribute(ObjectID.contentType);
        if (contentType != null) {
          System.out.println("The content has PKCS#7 content type " + contentType.getValue()[0]);
        }  
      } catch (SignatureException ex) {
         // if the signature is not OK a SignatureException is thrown
         System.out.println("Signature ERROR from signer: "+signed_data.getCertificate(signer_infos[i].getIssuerAndSerialNumber()).getSubjectDN());
         throw new iaik.pkcs.PKCSException(ex.toString());
      } catch (CodingException ex) {
         throw new iaik.pkcs.PKCSException("Attribute decoding error: " + ex.toString()); 
      } 
    }      
    
    // now check alternative signature verification
    System.out.println("Now check the signature assuming that no certs have been included:");
    try {
       iaik.pkcs.pkcs7.SignerInfo signer_info = signed_data.verify(user1Cert_);
        // if the signature is OK the certificate of the signer is returned
        System.out.println("Signature OK from signer: "+signed_data.getCertificate(signer_info.getIssuerAndSerialNumber()).getSubjectDN());
        
    } catch (SignatureException ex) {
        // if the signature is not OK a SignatureException is thrown
        System.out.println("Signature ERROR from signer: "+user1Cert_.getSubjectDN());
        throw new iaik.pkcs.PKCSException(ex.toString());
    }
       
    try {
       iaik.pkcs.pkcs7.SignerInfo signer_info = signed_data.verify(user2Cert_);
        // if the signature is OK the certificate of the signer is returned
        System.out.println("Signature OK from signer: "+signed_data.getCertificate(signer_info.getIssuerAndSerialNumber()).getSubjectDN());
        
    } catch (SignatureException ex) {
        // if the signature is not OK a SignatureException is thrown
        System.out.println("Signature ERROR from signer: "+user2Cert_.getSubjectDN());
        throw new iaik.pkcs.PKCSException(ex.toString());
    }    
    
    
    return signed_data.getContent();
  }
  
  
  /**
   * Tests the CMS SignedData implementation and checks it against the
   * IAIK PKCS#7 library.
   */
  public void start() {
     // the test message
    String m = "This is the test message.";
    System.out.println("Test message: \""+m+"\"");
    System.out.println();
    byte[] message = m.getBytes();
   
    try {
      byte[] data;
      byte[] received_message = null;
      System.out.println("Stream implementation demos");
      System.out.println("===========================");
     
      
      
      System.out.println("\nChecking against PKCS#7...");
      
      //
      // Implicit SignedDataStream: CMS (create), PKCS#7 (parse)
      //
      System.out.println("\nCreating implicit CMS SignedDataStream: \n");
      data = createSignedDataStream(message, SignedDataStream.IMPLICIT);
      // transmit data
      System.out.println("\nParse implicit CMS SignedDataStream with PKCS#7:\n");
      received_message = getPKCS7SignedDataStream(data, null);
      System.out.print("\nSigned content: ");
      System.out.println(new String(received_message));
      
      //
      // Explicit SignedDataStream: CMS (create), PKCS#7 (parse)
      //
      System.out.println("\nCreating explicit CMS SignedDataStream: \n");
      data = createSignedDataStream(message, SignedDataStream.EXPLICIT);
      // transmit data
      System.out.println("\nParse explicit CMS SignedDataStream SignedDataStream with PKCS#7:\n");
      received_message = getPKCS7SignedDataStream(data, message);
      System.out.print("\nSigned content: ");
      System.out.println(new String(received_message));
      
      //
      // Implicit SignedDataStream: PKCS#7 (create), CMS (parse)
      //
      System.out.println("\nCreating implicit PKCS#7 SignedDataStream: \n");
      data = createPKCS7SignedDataStream(message, SignedDataStream.IMPLICIT);
      // transmit data
      System.out.println("\nParse implicit PKCS#7 SignedDataStream with CMS:\n");
      received_message = getSignedDataStream(data, null);
      System.out.print("\nSigned content: ");
      System.out.println(new String(received_message));
      
      //
      // Explicit SignedDataStream: CMS (create), PKCS#7 (parse)
      //
      System.out.println("\nCreating explicit CMS SignedDataStream: \n");
      data = createSignedDataStream(message, SignedDataStream.EXPLICIT);
      // transmit data
      System.out.println("\nParse explicit SignedDataStream SignedDataStream with PKCS#7:\n");
      received_message = getPKCS7SignedDataStream(data, message);
      System.out.print("\nSigned content: ");
      System.out.println(new String(received_message));
      
       
      // the non-stream implementation
      System.out.println("\nNon-stream implementation demos");
      System.out.println("===============================");
   
      //
      // test PKCS#7 Data
      //
      ASN1Object obj = null;

      System.out.println("\nChecking against PKCS#7...");
      
      //
      // Implicit SignedData: CMS (create), PKCS#7 (parse)
      //
      System.out.println("\nCreating implicit CMS SignedData: \n");
       obj = createSignedData(message, SignedData.IMPLICIT);
      // transmit data
      System.out.println("\nParsing implicit CMS SignedData with PKCS#7:\n");
      received_message = getPKCS7SignedData(obj, null);
      System.out.print("\nSigned content: ");
      System.out.println(new String(received_message));

      //
      // Explicit SignedData: CMS (create), PKCS#7 (parse)
      //
      System.out.println("\nCreating explicit CMS SignedData: \n");
      obj = createSignedData(message, SignedData.EXPLICIT);
      // transmit data
      System.out.println("\nParsing explicit CMS SignedData with PKCS#7:\n");
      received_message = getPKCS7SignedData(obj, message);
      System.out.print("\nSigned content: ");
      System.out.println(new String(received_message));
      
      
      //
      // Implicit SignedData: PKCS#7 (create), CMS (parse)
      //
      System.out.println("\nCreating implicit PCSK#7 SignedData: \n");
       obj = createPKCS7SignedData(message, SignedData.IMPLICIT);
      // transmit data
      System.out.println("\nParsing implicit PKCS#7 SignedData with CMS:\n");
      received_message = getSignedData(obj, null);
      System.out.print("\nSigned content: ");
      System.out.println(new String(received_message));

      //
      // Explicit SignedData: PKCS#7 (create), CMS (parse)
      //
      System.out.println("\nCreating implicit PKCS#7 SignedData: \n");
      obj = createPKCS7SignedData(message, SignedData.EXPLICIT);
      // transmit data
      System.out.println("\nParsing explicit PKCS#7 SignedData with CMS:\n");
      received_message = getSignedData(obj, message);
      System.out.print("\nSigned content: ");
      System.out.println(new String(received_message));

   	} catch (Exception ex) {
   	  ex.printStackTrace();
   	  throw new RuntimeException(ex.toString());
   	}
  }
  
  /**
   * Main method. 
   *
   * @exception IOException 
   *            if an I/O error occurs when reading required keys
   *            and certificates from files
   */
  public static void main(String argv[]) throws Exception {

   	DemoUtil.initDemos();
    
    (new PKCS7CMSSignedDataDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}