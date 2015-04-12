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
// $Header: /IAIK-CMS/current/src/demo/cms/signedData/CounterSignatureDemo.java 26    23.08.13 14:29 Dbratko $
// $Revision: 26 $
//

package demo.cms.signedData;

import iaik.asn1.CodingException;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.asn1.structures.AttributeValue;
import iaik.cms.CMSException;
import iaik.cms.ContentInfo;
import iaik.cms.ContentInfoStream;
import iaik.cms.IssuerAndSerialNumber;
import iaik.cms.SignedData;
import iaik.cms.SignedDataStream;
import iaik.cms.SignerInfo;
import iaik.cms.attributes.CMSContentType;
import iaik.cms.attributes.CounterSignature;
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
 * This class demonstrates the usage of the CounterSignature attribute.
 * <p>
 * A {@link iaik.cms.attributes.CounterSignature CounterSignature} attribute may be included
 * as an unsigned attribute into a {@link iaik.cms.SignerInfo SignerInfo} for counter signing
 * (signing in serial) the signature value of a SignerInfo included in a SignedData. The value
 * of a CounterSignature attribute itself is a SignerInfo.
 * <p>
 * This demo shows how a CounterSignature attribute may be added to some SignerInfo that belongs
 * to a SignedData object just parsed/verified. This class demonstrates adding/verifying of a
 * CounterSignature attribute to both the {@link iaik.cms.SignedDataStream stream} and the
 * {@link iaik.cms.SignedData non-stream} implementations of the SignedData type. Since when
 * parsing an implicit -- where the content is included -- SignedData object, SignerInfos
 * can not accessed before the data has been processed, adding a counter signature to 
 * a {@link iaik.cms.SignedDataStream SignedDataStream} may require a different proceeding
 * than adding it to a {@link iaik.cms.SignedData SignedData} object. For that reason a
 * {@link CounterSignatureListener CounterSignatureListener} is used for the
 * stream demos to listen on and add the counter signature during the encoding process.
 *
 * @see CounterSignatureListener
 * @see iaik.cms.attributes.CounterSignature
 * @see iaik.cms.SDSEncodeListener
 * @see iaik.cms.SignedDataStream
 * @see iaik.cms.SignerInfo
 * 
 * @author Dieter Bratko
 */
public class CounterSignatureDemo {

  byte[] message;
  
  // signing certificate of user 1
  X509Certificate user1_sign;
  // signing private key of user 1
  PrivateKey user1_sign_pk;
  // signing certificate of user 2 (counter signer)
  X509Certificate user2_sign;
  // signing private key of user 2 (counter signer)
  PrivateKey user2_sign_pk;
  
  // a certificate chain containing the user certs + CA
  X509Certificate[] certificates;

  /**
   * Constructor.
   * Reads required keys/certs from the demo keystore.
   */
  public CounterSignatureDemo() {
    
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                      CounterSignatureDemo demo                                 *");
    System.out.println("*       (shows the usage of the CounterSignature attribute implementation)       *");
    System.out.println("**********************************************************************************");
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
   * @exception Exception if the <code>SignedData</code> object cannot
   *                      be created for some reason
   */
  public byte[] createSignedDataStream(byte[] message, int mode) throws Exception {

    System.out.println("Create a new message signed by user 1:");

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);
    // create a new SignedData object which includes the data
    SignedDataStream signed_data = new SignedDataStream(is, mode);
    
    // SignedData shall include the certificate chain for verifying
    signed_data.setCertificates(certificates);

    // cert at index 0 is the user certificate
    IssuerAndSerialNumber issuer = new IssuerAndSerialNumber(user1_sign);

    // create a new SignerInfo
    SignerInfo signer_info = new SignerInfo(issuer, (AlgorithmID)AlgorithmID.sha1.clone(), user1_sign_pk);
    // create some authenticated attributes
    // the message digest attribute is automatically added
    Attribute[] attributes = new Attribute[2];
    // content type is data
    attributes[0] = new Attribute(new CMSContentType(ObjectID.cms_data));
    // signing time is now
    attributes[1] = new Attribute(new SigningTime());
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
    // wrap into ContentInfo
    ContentInfoStream ci = new ContentInfoStream(signed_data);
    ci.writeTo(os);
    return os.toByteArray();
  }

  /**
   * Parses a CMS <code>SignedData</code> object and verifies the signatures
   * for all participated signers. 
   *
   * @param signedData the SignedData, as BER encoded byte array
   * @param message the the message which was transmitted out-of-band (explicit signed)
   * @param counterSign whether to use a SDSEncodeListener to add a SignerInfo
   *        and encode the SignedData again
   *
   * @return the inherent message as byte array, or the BER encoded SignedData if
   *         it shall be encoded again (counter signing phase)
   * @exception Exception if an error occurs
   */
  public byte[] getSignedDataStream(byte[] signedData, byte[] message, boolean counterSign) 
    throws Exception {

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(signedData);
    
    // the ByteArrayOutputStream to which to write the content
    ByteArrayOutputStream os = new ByteArrayOutputStream();
        
    SignedDataStream signed_data = new SignedDataStream(is);
    
    // content included (implicit mode)?
    boolean implicit = (signed_data.getMode() == SignedDataStream.IMPLICIT); 
    
    if (implicit == false) {
      // in explicit mode explicitly supply the content for hash computation  
      signed_data.setInputStream(new ByteArrayInputStream(message));
    }

    
    if (counterSign) {
      // we want to write the SignedData again   
      // we add a counter signature attribute to the first signer
            
      // add the CounterSignature via SDSEncodeListener
      CounterSignatureListener csl = 
        new CounterSignatureListener(new IssuerAndSerialNumber(user2_sign), 
                                     (AlgorithmID)AlgorithmID.sha256.clone(),
                                     user2_sign_pk);
      // we only want to counter sign some specific signer  
      csl.setCertOfSignerToBeCounterSigned(user1_sign);
      
      if (implicit) {
        // in implicit mode copy data to os
        csl.setOutputStream(os);
        signed_data.setSDSEncodeListener(csl);     

      } else {
        signed_data.setSDSEncodeListener(csl);
        // get an InputStream for reading the signed content
        InputStream data = signed_data.getInputStream();
        Util.copyStream(data, os, null);
      } 
       
      // ensure block encoding
      signed_data.setBlockSize(2048);
      // return the SignedData as encoded byte array with block size 2048
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      // wrap into ContentInfo
      ContentInfoStream ci = new ContentInfoStream(signed_data);
      ci.writeTo(baos);
      
      // we read the content
      byte[] content = os.toByteArray();
      System.out.println("Content: " + new String(content));
      
      // return encoded SignedData
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
          // signing time
          SigningTime signingTime = (SigningTime)signer_infos[i].getSignedAttributeValue(ObjectID.signingTime);
          if (signingTime != null) {
            System.out.println("This message has been signed at " + signingTime.get());
          } 
          // content type
          CMSContentType contentType = (CMSContentType)signer_infos[i].getSignedAttributeValue(ObjectID.contentType);
          if (contentType != null) {
            System.out.println("The content has CMS content type " + contentType.get().getName());
          }
          // counter signature?
          Attribute counterSignatureAttribute = signer_infos[i].getUnsignedAttribute(ObjectID.countersignature);
          if (counterSignatureAttribute != null) {
            AttributeValue[] counterSignatures = counterSignatureAttribute.getAttributeValues();
            System.out.println("This SignerInfo is counter signed from: ");
            for (int j = 0; j < counterSignatures.length; j++) {
              CounterSignature counterSignature = (CounterSignature)counterSignatures[j];
              try {
                if (counterSignature.verify(user2_sign.getPublicKey(), signer_infos[i])) {
                  System.out.println("Signature OK from counter signer: "+counterSignature.getSignerIdentifier());  
                } else {
                  System.out.println("Signature ERROR from counter signer: "+counterSignature.getSignerIdentifier());  
                }  
              } catch (SignatureException ex) {
                System.out.println("Signature ERROR from counter signer: "+counterSignature.getSignerIdentifier());  
                throw new CMSException(ex.toString());
              }  
              signingTime = (SigningTime)counterSignature.getSignedAttributeValue(ObjectID.signingTime);
              if (signingTime != null) {
                System.out.println("Counter signature has been created " + signingTime.get());
              } 
            }  
          }
          
        } catch (SignatureException ex) {
          // if the signature is not OK a SignatureException is thrown
          System.err.println("Signature ERROR from signer: "+signed_data.getCertificate((signer_infos[i].getSignerIdentifier())).getSubjectDN());
          throw new CMSException(ex.toString());
        } catch (CodingException ex) {
          throw new CMSException("Attribute decoding error: " + ex.toString());
        }
      }
      
      // return content
      return os.toByteArray();
    }
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
   * @exception Exception if an error occurs
   */
  public byte[] createSignedData(byte[] message, int mode) throws Exception  {

    System.out.println("Create a new message signed by user 1:");

    // create a new SignedData object
    SignedData signed_data = new SignedData(message, mode);
    
    // SignedData shall include the certificate chain for verifying
    signed_data.setCertificates(certificates);

    // cert at index 0 is the user certificate
    IssuerAndSerialNumber issuer = new IssuerAndSerialNumber(user1_sign);

    // create a new SignerInfo
    SignerInfo signer_info = new SignerInfo(issuer, (AlgorithmID)AlgorithmID.sha1.clone(), user1_sign_pk);
    // create some authenticated attributes
    // the message digest attribute is automatically added
    Attribute[] attributes = new Attribute[2];
    // content type is data
    attributes[0] = new Attribute(new CMSContentType(ObjectID.cms_data));
    // signing time is now
    attributes[1] = new Attribute(new SigningTime());
    // set the attributes
    signer_info.setSignedAttributes(attributes);
    // finish the creation of SignerInfo by calling method addSigner
    try {
      signed_data.addSignerInfo(signer_info);

    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("No implementation for signature algorithm: "+ex.getMessage());
    }
    
    // return the SignedData as encoded byte array with block size 2048
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    // wrap into ContentInfo
    ContentInfo ci = new ContentInfo(signed_data);
    ci.writeTo(os);
    return os.toByteArray();
  }

  /**
   * Parses a CMS <code>SignedData</code> object and verifies the signatures
   * for all participated signers. 
   *
   * @param signedData the SignedData, as BER encoded byte array
   * @param message the the message which was transmitted out-of-band (explicit signed)
   * @param counterSign whether to use a SDSEncodeListener to add a SignerInfo
   *        and encode the SignedData again
   *
   * @return the inherent message as byte array, or the BER encoded SignedData if
   *         it shall be encoded again (counter signing phase)
   * @exception Exception if any error occurs
   */
  public byte[] getSignedData(byte[] signedData, byte[] message, boolean counterSign) 
    throws Exception {

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(signedData);
        
    SignedData signed_data = new SignedData(is);
    
    // content included (implicit mode)?
    boolean implicit = (signed_data.getMode() == SignedData.IMPLICIT);
    if (implicit == false) {
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
        // get signed attributes
        // signing time
        SigningTime signingTime = (SigningTime)signer_infos[i].getSignedAttributeValue(ObjectID.signingTime);
        if (signingTime != null) {
          System.out.println("This message has been signed at " + signingTime.get());
        } 
        // content type
        CMSContentType contentType = (CMSContentType)signer_infos[i].getSignedAttributeValue(ObjectID.contentType);
        if (contentType != null) {
          System.out.println("The content has CMS content type " + contentType.get().getName());
        }
        // counter signature?
        Attribute counterSignatureAttribute = signer_infos[i].getUnsignedAttribute(ObjectID.countersignature);
        if (counterSignatureAttribute != null) {
          AttributeValue[] counterSignatures = counterSignatureAttribute.getAttributeValues();
          System.out.println("This SignerInfo is counter signed from: ");
          for (int j = 0; j < counterSignatures.length; j++) {
            CounterSignature counterSignature = (CounterSignature)counterSignatures[j];
            try {
              if (counterSignature.verify(user2_sign.getPublicKey(), signer_infos[i])) {
                System.out.println("Signature OK from counter signer: "+counterSignature.getSignerIdentifier());  
              } else {
                System.out.println("Signature ERROR from counter signer: "+counterSignature.getSignerIdentifier());  
              }  
            } catch (SignatureException ex) {
              System.out.println("Signature ERROR from counter signer: "+counterSignature.getSignerIdentifier());  
              throw new CMSException(ex.toString());
            }  
            signingTime = (SigningTime)counterSignature.getSignedAttributeValue(ObjectID.signingTime);
            if (signingTime != null) {
              System.out.println("Counter signature has been created " + signingTime.get());
            } 
          }  
        }    

      } catch (SignatureException ex) {
        // if the signature is not OK a SignatureException is thrown
        System.out.println("Signature ERROR from signer: "+signed_data.getCertificate((signer_infos[i].getSignerIdentifier())).getSubjectDN());
        throw new CMSException(ex.toString());
      } catch (CodingException ex) {
        throw new CMSException("Attribute decoding error: " + ex.toString());
      }
    }
    
    if (counterSign) {
      // we want to write the SignedData again   
      // we add a counter signature attribute to the first signer
      CounterSignature counterSignature = new CounterSignature(new IssuerAndSerialNumber(user2_sign),
          (AlgorithmID)AlgorithmID.sha256.clone(), user2_sign_pk);
      // create some authenticated attributes
      // the message digest attribute is automatically added
      // signing time is now
      SigningTime signingTime = new SigningTime();
      Attribute[] attributes = { new Attribute(signingTime) };
      // set the attributes
      counterSignature.setSignedAttributes(attributes);
      // now counter sign first SignerInfo
      counterSignature.counterSign(signer_infos[0]);
      // and add the counter signature as unsigned attribute
      Attribute[] usignedAttributes = { new Attribute(counterSignature) };
      signer_infos[0].addUnsignedAttributes(usignedAttributes);
      
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      ContentInfo ci = new ContentInfo(signed_data);
      ci.writeTo(baos);
      signed_data.writeTo(baos);
      
      // we read the content
      System.out.println("Content: " + new String(signed_data.getContent()));
      
      return baos.toByteArray();

    } else {
      // return the content     
      return signed_data.getContent();
    }  
    
    
  }

  /**
   * Starts the demo.
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
      System.out.println("\nImplicit SignedDataStream demo [counter sign]:\n");
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
      System.out.println("\nExplicit SignedDataStream demo [counter sign]:\n");
      data = getSignedDataStream(data, message, true);
      
      System.out.println("\nExplicit SignedDataStream demo [parse]:\n");
      received_message = getSignedDataStream(data, message, false);
      System.out.print("\nSigned content: ");
      System.out.println(new String(received_message));
      
      //
      // test CMS Implicit SignedData
      //
      System.out.println("\nImplicit SignedData demo [create]:\n");
      data = createSignedData(message, SignedData.IMPLICIT);
      // parse and encode again
      System.out.println("\nImplicit SignedData demo [counter sign]:\n");
      data = getSignedData(data, null, true);
      // parse
      System.out.println("\nImplicit SignedData demo [parse]:\n");
      received_message = getSignedData(data, null, false);
      System.out.print("\nSigned content: ");
      System.out.println(new String(received_message));

      //
      // test CMS Explicit SignedData
      //
      System.out.println("\nExplicit SignedData demo [create]:\n");
      data = createSignedData(message, SignedData.EXPLICIT);
      // parse and encode again
      System.out.println("\nExplicit SignedData demo [counter sign]:\n");
      data = getSignedData(data, message, true);
      
      System.out.println("\nExplicit SignedData demo [parse]:\n");
      received_message = getSignedData(data, message, false);
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
  public static void main(String argv[]) throws IOException {
   try {
     DemoUtil.initDemos();
     (new CounterSignatureDemo()).start();
     System.out.println("\nReady!");
   } catch (Exception ex) {    
     ex.printStackTrace();      
   }
   DemoUtil.waitKey();
  }
}
