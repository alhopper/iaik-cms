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
// $Header: /IAIK-CMS/current/src/demo/cms/pkcs11/SignedDataStreamDemo.java 12    8.11.13 17:13 Dbratko $
// $Revision: 12 $
//

package demo.cms.pkcs11;

// class and interface imports
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.cms.CMSException;
import iaik.cms.ContentInfoStream;
import iaik.cms.IssuerAndSerialNumber;
import iaik.cms.SignedDataStream;
import iaik.cms.SignerInfo;
import iaik.cms.attributes.CMSContentType;
import iaik.cms.attributes.SigningTime;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;


/**
 * Base class of SignedDataStream demos using PKCS#11 for
 * accessing the signer key on a smart card.
 * 
 * @author Dieter Bratko 
 */
public abstract class SignedDataStreamDemo extends PKCS11Demo {
  
   /**
   * The private key of the signer. In this case only a proxy object, but the
   * application cannot see this.
   */
  protected PrivateKey signerKey_;

  /**
   * This is the certificate used for verifying the signature. In contrast to the
   * private signer key, the certificate holds the actual public keying material.
   */
  protected X509Certificate signerCertificate_;

  /**
   * Creates a SignedDataStreamDemo object for the given module name.
   * 
   * @param moduleName the name of the module
   * @param userPin the user-pin (password) for the TokenKeyStore
   *                (may be <code>null</code> to pou-up a dialog asking for the pin)
   */
  protected SignedDataStreamDemo(String moduleName, char[] userPin) {
    // install provider in super class    
    super(moduleName, userPin);
  }

  /**
   * This method gets the key stores of all inserted (compatible) smart
   * cards and simply takes the first key-entry. From this key entry it
   * takes the private key and the certificate to retrieve the public key
   * from. The keys are stored in the member variables <code>signerKey_
   * </code> and <code>signerCertificate_</code>.
   *
   * @exception GeneralSecurityException If anything with the provider fails.
   * @exception IOException If loading the key store fails.
   */
  protected void getSignatureKey() throws GeneralSecurityException, IOException
  {
    // we simply take the first keystore, if there are serveral
    Enumeration aliases = tokenKeyStore_.aliases();

    // and we take the first signature (private) key for simplicity
    while (aliases.hasMoreElements()) {
      String keyAlias = aliases.nextElement().toString();
      Key key = null;
      try {
        key = tokenKeyStore_.getKey(keyAlias, null);
      } catch (NoSuchAlgorithmException ex) {
        throw new GeneralSecurityException(ex.toString());
      }

      if (key instanceof PrivateKey) {
        Certificate[] certificateChain = tokenKeyStore_.getCertificateChain(keyAlias);
        if ((certificateChain != null) && (certificateChain.length > 0)) {
          X509Certificate signerCertificate = (X509Certificate) certificateChain[0];
          boolean[] keyUsage = signerCertificate.getKeyUsage();
          if ((keyUsage == null) || keyUsage[0] || keyUsage[1]) { // check for digital signature or non-repudiation, but also accept if none set
            System.out.println("##########");
            System.out.println("The signer key is: " + key );
            System.out.println("##########");
            // get the corresponding certificate for this signer key
            System.out.println("##########");
            System.out.println("The signer certificate is:");
            System.out.println(signerCertificate.toString());
            System.out.println("##########");
            signerKey_ = (PrivateKey) key;
            signerCertificate_ = signerCertificate;
            break;
          }
        }  
      }
    }

    if (signerKey_ == null) {
      System.out.println("Found no signature key. Ensure that a valid card is inserted and contains a key that is suitable for signing.");
      System.exit(0);
    }
  }

  /**
   * This method signs the data in the byte array <code>DATA</code> with
   * <code>signatureKey_</code>. Normally the data would be read from file.
   * The created signature is stored in <code>signature_</code>.
   * 
   * @param data the data to be signed
   * @param implicit whether to include the data (implicit mode) 
   *                 or  to not include it (explicit mode)
   * 
   * @return the encoded SignedData
   *
   * @exception GeneralSecurityException
   *     If anything with the provider fails.
   * @exception IOException
   *     If the data file could not be found or writing to it failed.
   * @exception CMSException 
   *     If an error occurs when creating/encoding the SignedData     
   */
  public byte[] sign(byte[] data, boolean implicit)
      throws GeneralSecurityException, IOException, CMSException
  {    
    System.out.println("##########");
    System.out.print("Signing data... ");
    
    InputStream dataStream = new ByteArrayInputStream(data); // the raw data supplying input stream
    int mode = (implicit == true) ? SignedDataStream.IMPLICIT : SignedDataStream.EXPLICIT;
    SignedDataStream signedData = new SignedDataStream(dataStream, mode);
    iaik.x509.X509Certificate iaikSignerCertificate = (signerCertificate_ instanceof iaik.x509.X509Certificate) 
                                                       ? (iaik.x509.X509Certificate) signerCertificate_
                                                       : new iaik.x509.X509Certificate(signerCertificate_.getEncoded());
    signedData.setCertificates(new iaik.x509.X509Certificate[] { iaikSignerCertificate } );
    IssuerAndSerialNumber issuerAndSerialNumber = new IssuerAndSerialNumber(iaikSignerCertificate);
    SignerInfo signerInfo = new SignerInfo(issuerAndSerialNumber, (AlgorithmID)AlgorithmID.sha1.clone(), signerKey_);
    
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
    signerInfo.setSignedAttributes(attributes);
    
    try {
      signedData.addSignerInfo(signerInfo);
    } catch (NoSuchAlgorithmException ex) {
      throw new GeneralSecurityException(ex.toString());
    }
    
    if (implicit == false) {
      // in explicit mode read "away" content data (to be transmitted out-of-band)
      InputStream contentIs = signedData.getInputStream();
      byte[] buffer = new byte[2048];
      int bytesRead;
      while ((bytesRead = contentIs.read(buffer)) >= 0) {
        ;  // skip data
      }
    }
    
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    ContentInfoStream cos = new ContentInfoStream(signedData);
    cos.writeTo(baos);
    
    System.out.println("##########");
    
    return baos.toByteArray();
  }

  /**
   * This method verifies the signature stored in <code>signatureKey_
   * </code>. The verification key used is <code>verificationKey_</code>.
   * The implementation for the signature algorithm is taken from an
   * other provider. Here IAIK is used, IAIK is pure software.
   * 
   * @param encodedSignedData the encoded SignedData object
   * @param contentData the contentData (in explicit mode required for signature verification)
   * 
   * @return the content data
   *
   * @exception GeneralSecurityException
   *     If anything with the provider fails.
   * @exception IOException
   *     If reading the CMS file fails.
   * @exception CMSException
   *     If handling the CMS structure fails.
   * @exception SignatureException
   *     If the signature verification fails    
   */
  public byte[] verify(byte[] encodedSignedData, byte[] contentData)
      throws GeneralSecurityException, CMSException, IOException, SignatureException
  {
    System.out.println("##########");
    System.out.println("Verifying signature");
    
    InputStream inputStream = new ByteArrayInputStream(encodedSignedData); 
    SignedDataStream signedData = new SignedDataStream(inputStream);
    
    if (signedData.getMode() == SignedDataStream.EXPLICIT) {
      // explicitly set the data received by other means
      signedData.setInputStream(new ByteArrayInputStream(contentData));
    }
    
    // read data
    InputStream signedDataInputStream = signedData.getInputStream();

    ByteArrayOutputStream contentOs = new ByteArrayOutputStream();
    byte[] buffer = new byte[2048];
    int bytesRead;
    while ((bytesRead = signedDataInputStream.read(buffer)) >= 0) {
      contentOs.write(buffer, 0, bytesRead);
    }
    
    // get the signer infos
    SignerInfo[] signerInfos = signedData.getSignerInfos();
    // verify the signatures
    for (int i=0; i < signerInfos.length; i++) {
      try {
        // verify the signature for SignerInfo at index i
        X509Certificate signerCertificate = signedData.verify(i);
        // if the signature is OK the certificate of the signer is returned
        System.out.println("Signature OK from signer: "+ signerCertificate.getSubjectDN());
      } catch (SignatureException ex) {
        // if the signature is not OK a SignatureException is thrown
        throw new SignatureException("Signature ERROR: " + ex.getMessage());
      }
    }
    System.out.println("##########");
    // return the content
    return contentOs.toByteArray();
  }

}