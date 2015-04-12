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
// $Header: /IAIK-CMS/current/src/demo/cms/signedData/CounterSignatureListener.java 11    12.07.12 12:22 Dbratko $
// $Revision: 11 $
//

package demo.cms.signedData; 

import iaik.asn1.CodingException;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.cms.CMSException;
import iaik.cms.CertificateIdentifier;
import iaik.cms.SDSEncodeListener;
import iaik.cms.SignedDataStream;
import iaik.cms.SignerInfo;
import iaik.cms.attributes.CounterSignature;
import iaik.cms.attributes.SigningTime;
import iaik.x509.X509Certificate;

import java.security.PrivateKey;
import java.security.SignatureException;
import java.util.Date;

/**
 * A simple SignedDataStream encode listener implementation allowing an
 * application to add a CounterSignature attribute to some SignerInfo(s)
 * of a SignedDataStream (during the encoding is performed).
 * <p>
 * Using an SignedDataStream encode listener for adding a counter signature may
 * be useful when newly encoding an implicit SignedDataStream where the content data
 * is included and has to be written again to the new encoding. Since you cannot 
 * access the SignerInfo you wish to counter sign before the data is processed 
 * you need a mechanism to access and update the SignerInfo actually during the
 * encoding process. This mechanism is provided by this SDSEncodeListener.
 * <p>
 * This SDSEncodeListener implements method {@link #afterComputeSignature(SignedDataStream)
 * afterComputeSignature} to add a CounterSignature attribute to one particular or all of
 * the SignerInfos of a SignedData object. When creating a {@link 
 * #CounterSignatureListener(CertificateIdentifier, AlgorithmID, PrivateKey) creating} a
 * CounterSignatureListener information (ID, digest algorithm, (signature algorithm),
 * private key) about the counter signer has to be supplied. Optionally the SignerInfo 
 * to be counter signed may be explicitly {@link #setCertOfSignerToBeCounterSigned(X509Certificate)
 * identified} by the certificate of the corresponding original signer.
 * If not, a CounterSignature attribute will be created and added to any SignerInfo of the
 * SignedDataStream this SDSEncodeListener belongs to. 
 * <p>
 * This SDSEncodeListener implementation is part of the CounterSignature demo.
 * Please look at {@link CounterSignatureDemo CounterSignatureDemo}
 * for a usage example:
 * <pre>
 * // the SignedDataStream parsing an implicit SignedData:
 * SignedDataStream signedData = new SignedDataStream(inputStream);
 * ...
 * // the cert of the counter signer
 * X509Certificate counterCert = ...;
 * // the cert id of the counter signer:
 * IssuerAndSerialNumber counterID = new IssuerAndSerialNumber(counterCert);
 * // the private key of the counter signer:
 * PrivateKey counterKey = ...;
 * // use SHA-1 for hashing
 * AlgorithmID digestAlg = (AlgorithmID)AlgorithmID.sha1.clone();
 * // let an SDSEncodeListener create and add the CounterSignature attribute
 * CounterSignatureListener csl = new CounterSignatureListener(counterID, digestAlg, counterKey);
 * // we only want counter sign some specific signer
 * csl.setCertOfSignerToBeCounterSigned(signerCert);
 * // set the encode listener
 * signedData.setSDSEncodeListener(csl);     
 * ...
 * // encode again
 * signedData.writeTo(...);
 * </pre>
 * Note that this class only represents a simple demo for a SignedDataStream encode listener
 * that listens on the encoding procedure to add a counter signature to one specific or all
 * of the SignerInfos included in a SignedDataStream. Any counter signature attribute added
 * by this listener belongs to (i.e. is signed) by one and the same counter signer and only
 * contains a SigningTime and MessageDigest attribute as signed attributes. Any application
 * is free to implement its own CounterSignatureListener, e.g. to handle counter signatures
 * for more than one signer, or to add some more signed attributes...
 
 * 
 * @see CounterSignatureDemo
 * @see iaik.cms.attributes.CounterSignature
 * @see iaik.cms.SDSEncodeListener
 * @see iaik.cms.SignedDataStream
 * @see iaik.cms.SignerInfo
 * 
 * @author Dieter Bratko
 */
public class CounterSignatureListener extends SDSEncodeListener {
  // the cert id of the counter signer  
  CertificateIdentifier counterSigner_;  
  // the private key of the counter signer  
  PrivateKey privateKey_;   
  // the digest algorithm to be used
  AlgorithmID digestAlg_;
  // the signature algorithm to be used
  AlgorithmID signatureAlg_;
  // the cert of the signer to be counter signed
  X509Certificate certOfSignerToBeCounterSigned_;
  
  /**
   * Default constructor.
   * Sets rsaEncryption as default signature algorithm to be used.
   */
  CounterSignatureListener() {
    signatureAlg_ = (AlgorithmID)AlgorithmID.rsaEncryption.clone();
  }  
  
  /**
   * Creates a new CounterSignatureListener for the given
   * counter signer information. When using this constructor
   * for creating a CounterSignatureListener rsaEncryption will
   * be used for signing.
   *
   * @param counterSigner an id identifying the cert of the counter signer
   * @param digestAlgorithm the digest algorithm to be used
   * @param privateKey the private key of the counter signer
   */
  public CounterSignatureListener(CertificateIdentifier counterSigner, 
    AlgorithmID digestAlgorithm, PrivateKey privateKey) {
    this();    
    counterSigner_ = counterSigner;
    digestAlg_ = digestAlgorithm;
    privateKey_ = privateKey;
  }  
  
  /**
   * Creates a new CounterSignatureListener for the given
   * counter signer information. 
   *
   * @param counterSigner an id identifying the cert of the counter signer
   * @param digestAlgorithm the digest algorithm to be used
   * @param signatureAlgorithm the signature algorithm to be used
   * @param privateKey the private key of the counter signer
   */
  public CounterSignatureListener(CertificateIdentifier counterSigner, 
    AlgorithmID digestAlgorithm, AlgorithmID signatureAlgorithm, PrivateKey privateKey) {
    this(counterSigner, digestAlgorithm, privateKey);
    if (signatureAlgorithm != null) {
      signatureAlg_ = signatureAlgorithm;   
    }    
  }  

  
  /**
   * Identify the SignerInfo to be counter signed.
   * <p>
   * This method may be used for identifying the SignerInfo to be counter
   * signed by the certificate of the corresopnding signer. If set, any 
   * SignerInfo included in the SignedData is searched and a counter siganture
   * is only attached to the SignerInfo belonging to the given cert. If not set,
   * a counter signature is attched to any included SignerInfo.
   *
   * @param cert the cert of the signer to which the SignerInfo to be counter signed
   *             belongs
   */
  public void setCertOfSignerToBeCounterSigned(X509Certificate cert) {
    certOfSignerToBeCounterSigned_ = cert; 
  }  
  
  /**
   * Identifies the SignerInfo to be counter signed.
   * <p>
   * If {@link #setCertOfSignerToBeCounterSigned(X509Certificate) set}, the cert of the
   * signer to be counter signed is used to identify the corresponding SignerInfo. Any 
   * SignerInfo included in the SignedData is searched and a counter siganture
   * is only attached to the SignerInfo belonging to the given cert. If not set,
   * a counter signature is attched to any included SignerInfo.
   *
   * @return the cert of the signer to which the SignerInfo to be counter signed
   *         belongs, or <code>null</code> if not set
   */
  public X509Certificate getCertOfSignerToBeCounterSigned() {
    return certOfSignerToBeCounterSigned_; 
  }  
  
    
  /**
   * Does nothing.
   */
  protected void beforeComputeSignature(SignedDataStream signedData) 
    throws CMSException {
  }      
  
  /**
   * Calculates and adds a CounterSignature to all or some specific SignerInfo(s).
   * If the SignerInfo to be counter signed has not been 
   * explicitly {@link #setCertOfSignerToBeCounterSigned identified}
   * a CounterSignature is created and added to any SignerInfo of the SignedDataStream
   * this SDSEncodeListener belongs to. 
   * 
   * @param signedData the SignedDataStream to which to add a CounterSignature
   * @exception CMSException if the CounterSignature cannot be added (e.g. because
   *            the SignerInfo to which to add the counter signature cannot be
   *            verified)
   */
  protected void afterComputeSignature(SignedDataStream signedData) 
    throws CMSException {
     
     // is there a specific signer to be counter signed only
     if (certOfSignerToBeCounterSigned_ != null) {
       // search for a SignerInfo of this specific signer
       int index = searchForSignerInfoIndex(certOfSignerToBeCounterSigned_, signedData);
       if (index == -1) {
         throw new CMSException("Cannot counter sign " + certOfSignerToBeCounterSigned_.getSubjectDN() + ": No SignerInfo found!");
       } 
       try {
         signedData.verify(index);
         // counter sign signer info
         counterSign(signedData.getSignerInfos()[index]);   
            
       } catch (SignatureException ex) {
        // if the signature is not OK a SignatureException is thrown
        throw new CMSException("Signature verification ERROR from signer: "+ certOfSignerToBeCounterSigned_.getSubjectDN() + ex.getMessage());
      } 
         
     } else {  
       // counter sign any SignerInfo included
       SignerInfo[] signerInfos = signedData.getSignerInfos();  
       for (int i = 0; i < signerInfos.length; i++) {
         try {
           // verify the signed data using the SignerInfo at index i
           signedData.verify(i);
           // counter sign signer info
           counterSign(signerInfos[i]);
     
         } catch (SignatureException ex) {
           // if the signature is not OK a SignatureException is thrown
           throw new CMSException("Signature verification ERROR from signer: "+ signerInfos[i].getSignerIdentifier()+
                                  ex.getMessage());
         } 
       }
     }  
  }   
  
  /**
   * Counter signs the given signer info and adds the CounterSignature attribute to it.
   * 
   * @param signerInfo the SignerInfo to be counter signed
   * 
   * @exception SignatureException if the signature calculation fails
   * @exception CMSException if the CounterSignature attribute cannot be added
   */
  private void counterSign(SignerInfo signerInfo) throws SignatureException, CMSException {
    
    try {
      CounterSignature counterSignature = new CounterSignature(counterSigner_, digestAlg_, signatureAlg_, privateKey_);
      // add SigningTime attribute; the message digest attribute is automatically added
      // signing time is now
      Attribute[] attributes = new Attribute[] { new Attribute(new SigningTime(new Date())) };
      // set the attributes
      counterSignature.setSignedAttributes(attributes);  
      counterSignature.counterSign(signerInfo);  
      Attribute[] unsignedAttributes = new Attribute[] { new Attribute(counterSignature) };
      signerInfo.addUnsignedAttributes(unsignedAttributes);
    } catch (CodingException ex) {
      throw new CMSException("Error adding CounterSignature attribute: " + ex.toString());    
    }    
    
  }  
  
  /**
   * Searches for the index of the signerInfo belonging to the given signer certificate.
   *
   * @param signerCertificate the certificate of the signer
   * @param signedData the SignedData to be searched
   * @return the index of the signerInfo or -1 if there is no signerInfo matching to the
   *         given certificate
   */
  private static int searchForSignerInfoIndex(X509Certificate signerCertificate, SignedDataStream signedData) {
    SignerInfo[] signerInfos = signedData.getSignerInfos();
    if (signerInfos != null) {
      for (int i = 0; i < signerInfos.length; i++) {
        CertificateIdentifier signerIdentifier = signerInfos[i].getSignerIdentifier();
        if (signerIdentifier.identifiesCert(signerCertificate)) {
          return i; 
        }  
      }
    }  
    return -1;
  }  
    
}    