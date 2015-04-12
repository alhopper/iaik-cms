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
// $Header: /IAIK-CMS/current/src/demo/cms/signedData/SignedDataOutputStreamDemo.java 12    23.08.13 14:29 Dbratko $
// $Revision: 12 $
//

package demo.cms.signedData;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.asn1.structures.PolicyInformation;
import iaik.asn1.structures.PolicyQualifierInfo;
import iaik.cms.CMSException;
import iaik.cms.ContentInfoOutputStream;
import iaik.cms.IssuerAndSerialNumber;
import iaik.cms.SignedDataOutputStream;
import iaik.cms.SignedDataStream;
import iaik.cms.SignerInfo;
import iaik.cms.SubjectKeyID;
import iaik.cms.attributes.CMSContentType;
import iaik.cms.attributes.SigningTime;
import iaik.smime.ess.SigningCertificate;
import iaik.smime.ess.SigningCertificateV2;
import iaik.utils.Util;
import iaik.x509.X509Certificate;
import iaik.x509.X509ExtensionException;
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
 * Demonstrates the usage of class {@link iaik.cms.SignedDataOutputStream} and
 * {@link iaik.cms.SignedDataOutputStream} for signing some data using the CMS type
 * SignedData.
 * 
 * @author Dieter Bratko
 */
public class SignedDataOutputStreamDemo {

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
  public SignedDataOutputStreamDemo() throws IOException {
    
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                         SignedDataOutputStream demo                            *");
    System.out.println("*       (shows the usage of the CMS SignedDataOutputStream implementation)       *");
    System.out.println("**********************************************************************************");
    System.out.println();
    
    // add all certificates to the list
    user1Certs = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    user1 = (X509Certificate)user1Certs[0];
    user1_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    user2 = CMSKeyStore.getCertificateChain(CMSKeyStore.DSA, CMSKeyStore.SZ_1024_SIGN)[0];
    user2_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.DSA, CMSKeyStore.SZ_1024_SIGN);
    
    certs = user1Certs;
   
    certificates = new Certificate[certs.length+1];
    System.arraycopy(certs, 0, certificates, 0, certs.length);
    certificates[certs.length] = user2;
  }
  
  /**
   * Creates and encodes a CMS <code>SignedData</code> object.
   * <p>
   *
   * @param message the message to be signed, as byte representation
   * @param mode the transmission mode, either IMPLICIT or EXPLICIT
   * @return the BER encoding of the <code>SignedData</code> object just created, wrapped into a ContentInfo
   * @exception CMSException if the <code>SignedData</code> object cannot
   *                          be created
   * @exception IOException if some stream I/O error occurs
   */
  public byte[] createSignedDataStream(byte[] message, int mode) throws CMSException, IOException  {
    
    System.out.print("Create a new message signed by user 1 :");
    
    // a stream from which to read the data
    ByteArrayInputStream is = new ByteArrayInputStream(message);
    
    // the stream to which to write the SignedData
    ByteArrayOutputStream resultStream = new ByteArrayOutputStream();
    
    //  wrap SignedData into a ContentInfo 
    ContentInfoOutputStream contentInfoStream = 
      new ContentInfoOutputStream(ObjectID.cms_signedData, resultStream);
    SignedDataOutputStream signedData = new SignedDataOutputStream(contentInfoStream, mode);
    
    // add the certificates
    signedData.addCertificates(certificates);
    
    // cert at index 0 is the user certificate
    IssuerAndSerialNumber issuer = new IssuerAndSerialNumber(user1);

    // create a new SignerInfo
    SignerInfo signerInfo = new SignerInfo(issuer, (AlgorithmID)AlgorithmID.sha1.clone(), user1_pk);
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
      SigningCertificateV2 signingCertificate = new SigningCertificateV2(certs, true);
      String explicitText = "This certificate only may be used for test purposes";
      PolicyQualifierInfo policyQualifier = new PolicyQualifierInfo(null, null, explicitText);
      PolicyInformation[] policyInformations = 
        { new PolicyInformation(new ObjectID("1.3.6.1.4.1.2706.17.0.11.1.1"),
                              new PolicyQualifierInfo[] { policyQualifier }) };
      signingCertificate.setPolicies(policyInformations);                        
      System.out.println("Include signingCertificate attribute:");
      System.out.println(signingCertificate);
      attributes[2] = new Attribute(signingCertificate);
    } catch (Exception ex) {
      throw new CMSException("Error creating attribute: " + ex.toString());   
    }    
    // set the attributes
    signerInfo.setSignedAttributes(attributes);
    // finish the creation of SignerInfo by calling method addSigner
    try {
      signedData.addSignerInfo(signerInfo);
      // another SignerInfo without signed attributes and SHA-256 as hash algorithm
      signerInfo = new SignerInfo(new SubjectKeyID(user2), 
                                  (AlgorithmID)AlgorithmID.sha1.clone(), 
                                  (AlgorithmID)AlgorithmID.dsaWithSHA.clone(),
                                  user2_pk);
      
      // the message digest itself is protected
      signedData.addSignerInfo(signerInfo);

    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("No implementation for signature algorithm: "+ex.getMessage());
    } catch (X509ExtensionException ex) {
      throw new CMSException("Cannot create SubjectKeyID for user2 : " + ex.getMessage());
    }
    
    int blockSize = 4; // in real world we would use a block size like 2048
    //  write in the data to be signed
    byte[] buffer = new byte[blockSize];
    int bytesRead;
    while ((bytesRead = is.read(buffer)) != -1) {
      signedData.write(buffer, 0, bytesRead);
    }
    
    // closing the stream add the signer infos and closes the underlying stream
    signedData.close();
    return resultStream.toByteArray();
  }
  

  /**
   * Parses a CMS <code>SignedData</code> object and verifies the signatures
   * for all participated signers.
   *
   * @param signedData <code>SignedData</code> object (wrapped into a ContentInfo) as BER encoded byte array
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
          SigningCertificateV2 signingCertificate = signer_infos[i].getSigningCertificateV2Attribute();
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
      if (signedData.getSignerInfos()[signerInfoIndex].isSignerCertificate(signerCert) == false) {
        throw new CMSException("Cert ERROR!!! The certificate used for signing is not the one " +
                               "identified by the SignerCertificate attribute!");
      } else {
        System.out.println("SigningCertificate attribute: Signer cert ok!");   
      } 
      if (signingCertificate != null) {
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
    
  }      
  
  
  /**
   * Demonstrates the CMS SignedDataOutputStream implementation.
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
      // test CMS Implicit SignedDataOutputStream
      //
      System.out.println("\nImplicit SignedDataOutputStream demo [create]:\n");
      encoding = createSignedDataStream(message, SignedDataOutputStream.IMPLICIT);
      // transmit data
      System.out.println("\nImplicit SignedDataStream demo [parse]:\n");
      received_message = getSignedDataStream(encoding, null);
      System.out.print("\nSigned content: ");
      System.out.println(new String(received_message));
      
      //
      // test CMS Explicit SignedDataOutputStream
      //
      System.out.println("\nExplicit SignedDataOutputStream demo [create]:\n");
      encoding = createSignedDataStream(message, SignedDataOutputStream.EXPLICIT);
      // transmit data
      System.out.println("\nExplicit SignedDataStream demo [parse]:\n");
      received_message = getSignedDataStream(encoding, message);
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
    (new SignedDataOutputStreamDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}