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
// $Header: /IAIK-CMS/current/src/demo/smime/ess/SigningCertificateDemo.java 13    23.08.13 14:32 Dbratko $
// $Revision: 13 $
//

package demo.smime.ess;

import iaik.asn1.ASN1Object;
import iaik.asn1.ObjectID;
import iaik.asn1.SEQUENCE;
import iaik.asn1.UTF8String;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.asn1.structures.GeneralName;
import iaik.asn1.structures.GeneralNames;
import iaik.asn1.structures.Name;
import iaik.asn1.structures.PolicyInformation;
import iaik.asn1.structures.PolicyQualifierInfo;
import iaik.cms.CMSException;
import iaik.cms.IssuerAndSerialNumber;
import iaik.cms.SignedData;
import iaik.cms.SignedDataStream;
import iaik.cms.SignerInfo;
import iaik.cms.attributes.CMSContentType;
import iaik.cms.attributes.SigningTime;
import iaik.smime.ess.SigningCertificate;
import iaik.utils.Util;
import iaik.x509.X509Certificate;
import iaik.x509.attr.AttributeCertificate;
import iaik.x509.attr.Holder;
import iaik.x509.attr.V1Form;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

import demo.DemoUtil;
import demo.keystore.CMSKeyStore;


/**
 * Demonstrates how to add and parse a {@link iaik.smime.ess.SigningCertificate 
 * SigningCertificate} attribute to the SignerInfo of a {@link iaik.cms.SignedDataStream} or
 * {@link iaik.cms.SignedData} object. The SigningCertificate attributes maybe used
 * to include certificate identification information into the signed attributes of a 
 * CMS {@link iaik.cms.SignerInfo SignerInfo} object.
 *
 * @see iaik.smime.ess.SigningCertificate
 * @see iaik.cms.SignerInfo
 * @see iaik.cms.SignedDataStream
 * @see iaik.cms.SignedData
 * 
 * @author Dieter Bratko
 */
public class SigningCertificateDemo {

  // certificate of user 1
  X509Certificate user1;
  // private key of user 1
  PrivateKey user1_pk;

  // a certificate chain containing the user certs + CA
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
  public SigningCertificateDemo() throws IOException {
    
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                       SigningCertificateDemo demo                              *");
    System.out.println("*          (shows the usage of the ESS SigningCertificate attribute)             *");
    System.out.println("**********************************************************************************");
    System.out.println();
    
    // add all certificates to the list
    user1Certs = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    user1 = (X509Certificate)user1Certs[0];
    user1_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    
    certs = user1Certs;
    try {
      issuer1_pk = CMSKeyStore.getCaPrivateKey(CMSKeyStore.RSA);
      AttributeCertificate attrCert = createAttributeCertificate();
      certs = new Certificate[user1Certs.length+1];  
      System.arraycopy(user1Certs, 0, certs, 0, user1Certs.length);
      certs[user1Certs.length] = attrCert;
    } catch (CMSException ex) {
      System.out.println("No attribute certificates!");   
    }    
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
    signed_data.setCertificates(certs);
    
    // cert at index 0 is the user certificate
    IssuerAndSerialNumber issuer = new IssuerAndSerialNumber(user1);

    // create a new SignerInfo
    SignerInfo signer_info = new SignerInfo(issuer, (AlgorithmID)AlgorithmID.sha1.clone(), user1_pk);
    // create some authenticated attributes
    // the message digest attribute is automatically added
    Attribute[] attributes = new Attribute[3];
    try {
      // content type is data
      CMSContentType contentType = new CMSContentType(ObjectID.cms_data);
      attributes[0] = new Attribute(contentType);
      // signing time is now
      SigningTime signingTime = new SigningTime();
      attributes[1] = new Attribute(signingTime);
      // signing certificate
      SigningCertificate signingCertificate = createSigningCertificate(certs);
      String explicitText = "This certificate only may be used for test purposes";
      PolicyQualifierInfo policyQualifier = new PolicyQualifierInfo(null, null, explicitText);
      PolicyInformation[] policyInformations = 
        { new PolicyInformation(new ObjectID("1.3.6.1.4.1.2706.2.2.4.1.1.1.1"),
                              new PolicyQualifierInfo[] { policyQualifier }) };
      signingCertificate.setPolicies(policyInformations);                        
      System.out.println("Include signingCertificate attribute:");
      System.out.println(signingCertificate);
      attributes[2] = new Attribute(signingCertificate);
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
        
      try {
        // verify the signed data using the SignerInfo at index i
        X509Certificate signer_cert = signed_data.verify(i);
        // if the signature is OK the certificate of the signer is returned
        System.out.println("Signature OK from signer: "+signer_cert.getSubjectDN());
        SigningTime signingTime = (SigningTime)signer_infos[i].getSignedAttributeValue(ObjectID.signingTime);
        if (signingTime != null) {
          System.out.println("This message has been signed at " + signingTime.get());
        } 
        CMSContentType contentType = (CMSContentType)signer_infos[i].getSignedAttributeValue(ObjectID.contentType);
        if (contentType != null) {
          System.out.println("The content has CMS content type " + contentType.get().getName());
        }
        // check SigningCertificate attribute
        try {
          SigningCertificate signingCertificate = getSigningCertificate(signer_infos[i]);
          if (signingCertificate != null) {
            checkSigningCertificate(signingCertificate, signer_cert, signed_data, i);  
          }  
        } catch (CMSException ex) {
          throw new CMSException("Error parsing SigningCertificate attribute: " + ex.getMessage());   
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
  
    System.out.println("Included attribute certificates:");
    AttributeCertificate[] attributeCerts = signed_data.getAttributeCertificates();
    if (attributeCerts == null) {
      System.out.println("No attribute certificates");   
    } else {   
      for (int i = 0; i < attributeCerts.length; i++) {
        System.out.println(attributeCerts[i].getHolder());   
      } 
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
    signed_data.setCertificates(certs);
  
    // cert at index 0 is the user certificate
    IssuerAndSerialNumber issuer = new IssuerAndSerialNumber(user1);

    // create a new SignerInfo
    SignerInfo signer_info = new SignerInfo(issuer, (AlgorithmID)AlgorithmID.sha1.clone(), user1_pk);
    // create some authenticated attributes
    // the message digest attribute is automatically added
    Attribute[] attributes = new Attribute[3];
    try {
      // content type is data
      CMSContentType contentType = new CMSContentType(ObjectID.cms_data);
      attributes[0] = new Attribute(contentType);
      // signing time is now
      SigningTime signingTime = new SigningTime();
      attributes[1] = new Attribute(signingTime);
      // signing certificate
      SigningCertificate signingCertificate = createSigningCertificate(certs);
      System.out.println("Include signingCertificate attribute:");
      System.out.println(signingCertificate);
      attributes[2] = new Attribute(signingCertificate);
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
      try {
        // verify the signed data using the SignerInfo at index i
        X509Certificate signer_cert = signed_data.verify(i);
        // if the signature is OK the certificate of the signer is returned
        System.out.println("Signature OK from signer: "+signer_cert.getSubjectDN());
        SigningTime signingTime = (SigningTime)signer_infos[i].getSignedAttributeValue(ObjectID.signingTime);
        if (signingTime != null) {
          System.out.println("This message has been signed at " + signingTime.get());
        } 
        CMSContentType contentType = (CMSContentType)signer_infos[i].getSignedAttributeValue(ObjectID.contentType);
        if (contentType != null) {
          System.out.println("The content has CMS content type " + contentType.get().getName());
        }
        // check SigningCertificate attribute
        SigningCertificate signingCertificate = getSigningCertificate(signer_infos[i]);
        if (signingCertificate != null) {
          checkSigningCertificate(signingCertificate, signer_cert, signed_data, i);
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
      
    return signed_data.getContent();
  }
  
  /**
   * Checks the SigningCertificate attribute.
   *
   * @param signingCertificate the SigningCertificate attribute
   * @param signerCert the certificate of the signer
   * @param signedData the SignedData containing the SignerInfo with the SigningCertificate
   *                   attribute to be checked
   * @param signerInfoIndex the index of the SignerInfo with the SigningCertificate
   *                   attribute to be checked
   *
   * @exception CMSException if the SigningCertificate check fails
   */
  private void checkSigningCertificate(SigningCertificate signingCertificate,
                                       X509Certificate signerCert,
                                       SignedDataStream signedData,
                                       int signerInfoIndex) throws CMSException {
    try {
      if (signingCertificate != null) {
        System.out.println("SigningCertificate attribute included!");
        if (!signingCertificate.isSignerCertificate(signerCert)) {
          throw new CMSException("Cert ERROR!!! The certificate used for signing is not the one " +
                                 "identified by the SignerCertificate attribute!");
        } else {
          System.out.println("SigningCertificate attribute: Signer cert ok!");   
        } 
        // get the authorization certs for this signerInfo
        Certificate[] authCerts = 
          signingCertificate.getAuthorizedCertificates(signedData.getCertificates());
        if (authCerts != null) {
          System.out.println("SignedData contains the following authorization certs for SignerInfo No " + (signerInfoIndex+1) +":");   
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
            signingCertificate.getPolicyInformationCerts(signedData.getCertificates());
          if (policyCerts != null) {
            System.out.println("SignedData contains the following certs corresponding to policy informations of SignerInfo No "
                               + (signerInfoIndex+1) +":");   
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
    } 
  }      
  
  /**
   * Creates an attribute certificate just for testing.
   *
   * @return the attribute certificate created
   * @exception CMSException if an error occurs when creating the attribute certificate
   */
  public AttributeCertificate createAttributeCertificate() throws CMSException {
    try {
     
      Name issuer = (Name)user1.getIssuerDN();
      GeneralName genName = new GeneralName(GeneralName.directoryName, issuer);
      GeneralNames genNames = new GeneralNames(genName);
      V1Form v1Form = new V1Form(genNames);
      Name subject = (Name)user1.getSubjectDN();
      GeneralName genName1 = new GeneralName(GeneralName.directoryName, subject);
      GeneralNames genNames1 = new GeneralNames(genName1);
      Holder holder = new Holder();
      holder.setEntityName(genNames1);

      AttributeCertificate cert = new AttributeCertificate();
      cert.setHolder(holder);
      cert.setIssuer(v1Form);
      cert.setSerialNumber(new BigInteger("27"));
      GregorianCalendar c = new GregorianCalendar();
      Date notBeforeTime = c.getTime();
      c.add(Calendar.MONTH, 1);
      Date notAfterTime = c.getTime();
      cert.setNotBeforeTime(notBeforeTime);
      cert.setNotAfterTime(notAfterTime);
      Attribute[] attributes = new Attribute[1];
      // just for testing some abritrary attribute
      SEQUENCE postalAddress = new SEQUENCE();
      postalAddress.addComponent(new UTF8String("A-8010 Graz, Austria"));
      postalAddress.addComponent(new UTF8String("Inffeldgasse 16A"));
      attributes[0] = new Attribute(ObjectID.postalAddress, new ASN1Object[] {postalAddress});
      cert.setAttributes(attributes);
      cert.sign((AlgorithmID)AlgorithmID.sha1WithRSAEncryption_.clone(), issuer1_pk);
      cert.verify(user1Certs[1].getPublicKey());
      return cert;
    } catch (Exception ex) {
      throw new CMSException("Error creating attribute certificate: " + ex.toString());   
    }    
  
  }  

  /**
   * Starts the demo.
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
   * Creates a SigningCertificate attribute for the given certificates.
   * 
   * @param certs the certificates for which to create the SigningCertificate
   *              attribute
   *              
   * @return the SigningCertificate attribute just created             
   *              
   * @exception CMSException if an error occurs when creating the
   *                      SigningCertificate attribute             
   */
  protected SigningCertificate createSigningCertificate(Certificate[] certs) 
    throws CMSException {
    
    try {
      return new SigningCertificate(certs, true);
    } catch (Exception ex) {
      throw new CMSException("Error creating SigningCertificate attribute: " + ex.toString());
    }
  }
  
  /**
   * Gets the SigningCertificate attribute from the given SignerInfo.
   * 
   * @param signerInfo the SignerInfo from which to get the
   *                   SigningCertificate attribute
   *                   
   * @return the SigningCertificate attribute, or <code>null</code>
   *         if no SigningCertificate attribute is included  
   *         
   * @exception CMSException if an error occurs when getting the
   *                         SigningCertificate attribute                              
   */
  protected SigningCertificate getSigningCertificate(SignerInfo signerInfo)
    throws CMSException {
    
    return signerInfo.getSigningCertificateAttribute();
  }
  
  /**
   * Prints some header lines to System.out.
   */
  protected void printHeader() {
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                       SigningCertificateDemo demo                              *");
    System.out.println("*          (shows the usage of the ESS SigningCertificate attribute)             *");
    System.out.println("**********************************************************************************");
    System.out.println();
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
    (new SigningCertificateDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}