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
// $Header: /IAIK-CMS/current/src/demo/cms/basic/CMSDemo.java 38    23.08.13 14:20 Dbratko $
// $Revision: 38 $
//

package demo.cms.basic;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.cms.AuthenticatedData;
import iaik.cms.AuthenticatedDataStream;
import iaik.cms.CMSException;
import iaik.cms.ContentInfo;
import iaik.cms.ContentInfoStream;
import iaik.cms.Data;
import iaik.cms.DataStream;
import iaik.cms.DigestedData;
import iaik.cms.DigestedDataStream;
import iaik.cms.EncryptedContentInfo;
import iaik.cms.EncryptedContentInfoStream;
import iaik.cms.EncryptedData;
import iaik.cms.EncryptedDataStream;
import iaik.cms.EnvelopedData;
import iaik.cms.EnvelopedDataStream;
import iaik.cms.IssuerAndSerialNumber;
import iaik.cms.KeyTransRecipientInfo;
import iaik.cms.RecipientInfo;
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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.spec.InvalidParameterSpecException;

import demo.DemoUtil;
import demo.keystore.CMSKeyStore;

/**
 * This class shows some CMS examples where the content types are
 * wrapped into a ContentInfo.
 * <p>
 * All keys and certificates are read from a keystore created by the
 * SetupCMSKeyStore program.
 * <p>
 * This class demonstrates how to wrap the several CMS types into ContentInfos:
 * <p><ul>
 * <li>Data
 * <li>AuthenticatedData
 * <li>EncryptedData for PBE encrypting the content
 * <li>EnvelopedData
 * <li>DigestedData including the message
 * <li>DigestedData without message
 * <li>SignedData including the message
 * <li>SignedData without message
 * </ul><p>
 * Additionally, a <i>SignedAndEncryptedData</i> test is performed, which
 * is a sequential combination of signed and enveloped data content types.
 * <p>
 * All sub-tests use the same proceeding: A test message is properly
 * processed to give the requested content type object, which subsequently
 * is encoded to be "sent" to some recipient, who parses it for the
 * inherent structures.
 * 
 * @author Dieter Bratko
 */
public class CMSDemo {

  // signing certificate of user 1
  X509Certificate user1_sign;
  // signing private key of user 1
  PrivateKey user1_sign_pk;
  // signing certificate of user 2
  X509Certificate user2_sign;
  // signing private key of user 2
  PrivateKey user2_sign_pk;
  
  // encryption certificate of user 1
  X509Certificate user1_crypt;
  // encryption private key of user 1
  PrivateKey user1_crypt_pk;
  // encryption certificate of user 2
  X509Certificate user2_crypt;
  // encryption private key of user 2
  PrivateKey user2_crypt_pk;
  // a certificate chain containing the user certs + CA
  
  X509Certificate[] certificates;


  /**
   * Setup the demo certificate chains.
   *
   * Keys and certificate are retrieved from the demo KeyStore.
   *
   * @exception IOException if an file read error occurs
   */
  public CMSDemo() throws IOException {
    
    System.out.println();
    System.out.println("***************************************************************************************");
    System.out.println("*                                 Basic CMS Demo                                      *");
    System.out.println("*        (shows the usage of the several CMS content type implementations)            *");
    System.out.println("***************************************************************************************");
    System.out.println();
    
    
    // signing certs
    X509Certificate[] certs = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    user1_sign = certs[0];
    user1_sign_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    user2_sign = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_2048_SIGN)[0];
    user2_sign_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_2048_SIGN);
    certificates = new X509Certificate[certs.length+1];
    System.arraycopy(certs, 0, certificates, 0, certs.length);
    certificates[certs.length] = user2_sign;
    
    // encryption certs
    user1_crypt = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT)[0];
    user1_crypt_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT);
    user2_crypt = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_)[0];
    user2_crypt_pk = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_);

  }

  /**
   * Creates a CMS <code>Data</code> object and wraps it into a ContentInfo.
   * <p>
   * @param message the message to be sent, as byte representation
   * @return the encoded ContentInfo containing the <code>Data</code> object just created
   * @exception CMSException if the <code>Data</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createDataStream(byte[] message) throws CMSException, IOException  {

    System.out.println("Create a new Data message:");

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);

    // create a new Data object which includes the data
    DataStream data = new DataStream(is, 2048);

    ContentInfoStream cis = new ContentInfoStream(data);
    // return the ContentInfo as BER encoded byte array where Data is encoded with block size 2048
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    cis.writeTo(os);
    return os.toByteArray();
  }

  /**
   * Parses a CMS <code>Data</code> object.
   *
   * @param data the encoded ContentInfo holding the <code>Data</code>
   *
   * @return the inherent message as byte array
   * @exception CMSException if an parsing exception occurs
   * @exception IOException if an I/O error occurs
   */
  public byte[] getDataStream(byte[] data) throws CMSException, IOException {

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(data);
    ContentInfoStream cis = new ContentInfoStream(is);
    System.out.println("This ContentInfo holds content of type " + cis.getContentType().getName());
    // create the Data object
    DataStream dataStream = (DataStream)cis.getContent();

    // get an InputStream for reading the signed content
    InputStream content = dataStream.getInputStream();
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    Util.copyStream(content, os, null);

    return os.toByteArray();
  }

  /**
   * Creates a CMS <code>EnvelopedData</code> and wraps it into a ContentInfo.
   *
   * @param message the message to be enveloped, as byte representation
   * @return the encoded ContentInfo containing the EnvelopedData object just created
   *
   * @exception CMSException if the <code>EnvelopedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createEnvelopedDataStream(byte[] message) throws CMSException, IOException {

    EnvelopedDataStream enveloped_data;

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);
    // create a new EnvelopedData object encrypted with TripleDES CBC
    try {
      enveloped_data = new EnvelopedDataStream(is, (AlgorithmID)AlgorithmID.des_EDE3_CBC.clone());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("No implementation for Triple-DES-CBC.");
    }

    // create the recipient infos
    RecipientInfo[] recipients = new RecipientInfo[2];
    // user1 is the first receiver
    recipients[0] = new KeyTransRecipientInfo(user1_crypt, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // user2 is the second receiver
    recipients[1] = new KeyTransRecipientInfo(user2_crypt, (AlgorithmID)AlgorithmID.rsaEncryption.clone());

    // specify the recipients of the encrypted message
    enveloped_data.setRecipientInfos(recipients);

    // return the EnvelopedDate as DER encoded byte array with block size 2048
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    enveloped_data.setBlockSize(2048);
    ContentInfoStream cis = new ContentInfoStream(enveloped_data);
    cis.writeTo(os);
    return os.toByteArray();
  }

  /**
   * Decrypts the encrypted content of the given EnvelopedData object for the
   * specified recipient and returns the decrypted (= original) message.
   *
   * @param encoding the encoded ContentInfo containing an EnvelopedData object
   * @param privateKey the private key to decrypt the message
   * @param recipientInfoIndex the index into the <code>RecipientInfo</code> array
   *                           to which the specified private key belongs
   *
   * @return the recovered message, as byte array
   * @exception CMSException if the message cannot be recovered
   * @exception IOException if an I/O error occurs
   */
  public byte[] getEnvelopedDataStream(byte[] encoding, PrivateKey privateKey, int recipientInfoIndex) throws CMSException, IOException {

    // create the EnvelopedData object from a DER encoded byte array
    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    ContentInfoStream cis = new ContentInfoStream(is);
    EnvelopedDataStream enveloped_data = (EnvelopedDataStream)cis.getContent();

    System.out.println("Information about the encrypted data:");
    EncryptedContentInfoStream eci = (EncryptedContentInfoStream)enveloped_data.getEncryptedContentInfo();
    System.out.println("Content type: "+eci.getContentType().getName());
    System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());

    System.out.println("\nThis message can be decrypted by the owners of the following certificates:");
    RecipientInfo[] recipients = enveloped_data.getRecipientInfos();
    for (int i=0; i<recipients.length; i++) {
      System.out.println("Recipient "+(i+1)+":");
      System.out.println(recipients[i].getRecipientIdentifiers()[0]);
    }

    // decrypt the message
    try {
      enveloped_data.setupCipher(privateKey, recipientInfoIndex);
      InputStream decrypted = enveloped_data.getInputStream();
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      Util.copyStream(decrypted, os, null);

      return os.toByteArray();

    } catch (InvalidKeyException ex) {
      throw new CMSException("Private key error: "+ex.toString());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.toString());
    }
  }

  /**
   * Creates a CMS <code>SignedData</code> object ans wraps it into a ContentInfo.
   * <p>
   *
   * @param message the message to be signed, as byte representation
   * @param mode the mode indicating whether to include the content 
   *        (SignedDataStream.IMPLICIT) or not (SignedDataStream.EXPLICIT)
   * @return the encoding of the ContentInfo holding the <code>SignedData</code> object just created
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
    // SignedData shall include the certificate chain for verifying
    signed_data.setCertificates(certificates);

    // cert at index 0 is the user certificate
    IssuerAndSerialNumber issuer = new IssuerAndSerialNumber(user1_sign);

    // create a new SignerInfo
    SignerInfo signer_info = new SignerInfo(issuer, (AlgorithmID)AlgorithmID.sha1.clone(), user1_sign_pk);
    
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

      // another SignerInfo without authenticated attributes and RIPEMD-160 as hash algorithm
      signer_info = new SignerInfo(new IssuerAndSerialNumber(user2_sign),
          (AlgorithmID)AlgorithmID.ripeMd160.clone(), user2_sign_pk);
      // the message digest itself is protected
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

    // create the ContentInfo
    ContentInfoStream cis = new ContentInfoStream(signed_data);
    // return the SignedData as encoded byte array with block size 2048
    ByteArrayOutputStream os = new ByteArrayOutputStream();

    cis.writeTo(os);
    return os.toByteArray();
  }

  /**
   * Parses a CMS <code>SignedData</code> object and verifies the signatures
   * for all participated signers.
   *
   * @param signedData the ContentInfo with inherent SignedData, as BER encoded byte array
   * @param message the the message which was transmitted out-of-band (explicit signed)
   *
   * @return the inherent message as byte array, or <code>null</code> if there
   *         is no message included into the supplied <code>SignedData</code>
   *         object
   * @exception CMSException if any signature does not verify
   * @exception IOException if an I/O error occurs
   */
  public byte[] getSignedDataStream(byte[] signedData, byte[] message) throws CMSException, IOException {

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(signedData);
    // create the ContentInfo object
    SignedDataStream signed_data = new SignedDataStream(is);

    if (signed_data.getMode() == SignedDataStream.EXPLICIT) {
      // explicitly signed; set the content received by other means
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

  
  /**
   * Creates a <i>SignedAndEncrypted</i> (i.e. sequential combination of <code>
   * SignedData</code> and <code>EnvelopedData</code>). 
   *
   * @param message the message to be signed and encrypted, as byte representation
   * @return the encoded ContentInfo holding the signed and encrypted message object
   *         just created
   * @exception CMSException if the the <code>SignedData</code> or
   *                          <code>EnvelopedData</code> object cannot be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createSignedAndEncryptedDataStream(byte[] message) throws CMSException, IOException {

    System.out.println("Create a new message signed by user1 encrypted for user2:");

    byte[] signed = createSignedDataStream(message, SignedData.IMPLICIT);
    return createEnvelopedDataStream(signed);
  }

  /**
   * Recovers the original message and verifies the signature.
   *
   * @param in the encoded CMS object
   * @return the recovered message, as byte array
   * @exception CMSException if the message cannot be recovered
   * @exception IOException if an I/O error occurs
   */
  public byte[] getSignedAndEncryptedDataStream(byte[] in) throws CMSException, IOException {

    // user2 means index 2 (hardcoded for this demo)
    byte[] signed = getEnvelopedDataStream(in, user2_crypt_pk, 1);
    return getSignedDataStream(signed, null);
  }


   /**
   * Creates a CMS <code>DigestedData</code> object.
   * <p>
   * @param message the message to be digested, as byte representation
   * @return the encoded ContentInfo containing the DigestedData object just created
   * @exception CMSException if the <code>DigestedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createDigestedDataStream(byte[] message, int mode) throws CMSException, IOException  {

    System.out.println("Create a new message to be digested:");

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);

    // create a new DigestedData object which includes the data
    DigestedDataStream digested_data = null;

    digested_data = new DigestedDataStream(is, (AlgorithmID)AlgorithmID.sha256.clone(), mode);
    digested_data.setBlockSize(2048);

    // write the data through DigestedData to any out-of-band place
    if (mode == DigestedDataStream.EXPLICIT) {
      InputStream data_is = digested_data.getInputStream();
      byte[] buf = new byte[1024];
      int r;
      while ((r = data_is.read(buf)) > 0)
        ;   // skip data
    }

    // wrap into ContentInfo and encode
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    ContentInfoStream cis = new ContentInfoStream(digested_data);
    cis.writeTo(os);
    return os.toByteArray();
  }

  /**
   * Parses a CMS <code>DigestedData</code> object and verifies the hash.
   *
   * @param digestedData the encoded ContentInfo holding a DigestedData object
   * @param message the the message which was transmitted out-of-band
   *
   * @return the inherent message as byte array, or <code>null</code> if there
   *         is no message included into the supplied <code>DigestedData</code>
   *         object
   * @exception CMSException if any signature does not verify
   * @exception IOException if an I/O error occurs
   */
  public byte[] getDigestedDataStream(byte[] digestedData, byte[] message) throws CMSException, IOException {

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(digestedData);
    // create the DigestedData object
    DigestedDataStream digested_data = new DigestedDataStream(is);
    if (digested_data.getMode() == DigestedDataStream.EXPLICIT) {
      digested_data.setInputStream(new ByteArrayInputStream(message));
    }

    // get an InputStream for reading the signed content
    InputStream data = digested_data.getInputStream();
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    Util.copyStream(data, os, null);

    if (digested_data.verify()) {
      System.out.println("Hash ok!");
    } else {
      throw new CMSException("Hash verification failed!");
    }

    return os.toByteArray();
  }

  /**
   * Creates a CMS <code>EncryptedDataStream</code> message.
   * <p>
   * The supplied content is PBE-encrypted using the specified password.
   *
   * @param message the message to be encrypted, as byte representation
   * @param pbeAlgorithm the PBE algorithm to be used
   * @param password the password
   * @return the DER encoding of the ContentInfo holding the <code>EncryptedData</code> object just created
   * @exception CMSException if the <code>EncryptedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createEncryptedDataStream(byte[] message, AlgorithmID pbeAlgorithm, char[] password) throws CMSException, IOException {

    EncryptedDataStream encrypted_data;

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);
   
    try {
      encrypted_data = new EncryptedDataStream(is, 2048);
      encrypted_data.setupCipher(pbeAlgorithm, password);
    } catch (InvalidKeyException ex) {
      throw new CMSException("Key error: "+ex.toString());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.toString());
    }

    // wrap into ContentInfo and encode
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    ContentInfoStream cis = new ContentInfoStream(encrypted_data);
    cis.writeTo(os);
    return os.toByteArray();
  }

  /**
   * Decrypts the PBE-encrypted content of the given <code>EncryptedData</code> object
   * using the specified password and returns the decrypted (= original) message.
   *
   * @param encoding the encoded ContentInfo holding an <code>EncryptedData</code> object
   * @param password the password to decrypt the message
   *
   * @return the recovered message, as byte array
   * @exception CMSException if the message cannot be recovered
   * @exception IOException if an I/O error occurs
   */
  public byte[] getEncryptedDataStream(byte[] encoding, char[] password) throws CMSException, IOException {

    // create the EncryptpedData object from a DER encoded byte array
    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
     // create the ContentInfo
    ContentInfoStream cis = new ContentInfoStream(is);

    EncryptedDataStream encrypted_data = (EncryptedDataStream)cis.getContent();

    System.out.println("Information about the encrypted data:");
    EncryptedContentInfoStream eci = encrypted_data.getEncryptedContentInfo();
    System.out.println("Content type: "+eci.getContentType().getName());
    System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());

    // decrypt the message
    try {
      encrypted_data.setupCipher(password);
      InputStream decrypted = encrypted_data.getInputStream();
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      Util.copyStream(decrypted, os, null);

      return os.toByteArray();

    } catch (InvalidKeyException ex) {
      throw new CMSException("Key error: "+ex.toString());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.getMessage());
    } catch (InvalidAlgorithmParameterException ex) {
      throw new CMSException("Invalid Parameters: "+ex.getMessage());
    } catch (InvalidParameterSpecException ex) {
      throw new CMSException("Invalid Parameters: "+ex.getMessage());
    }
  }
  
  /**
   * Creates a CMS <code>AuthenticatedDataStream</code> for the given message message.
   * <p>
   * <b>Attention:</b> This AuthenticatedData demo uses RSA as key management technique.
   * In practice (see RFC 5652) a key management technique that provides data origin
   * authentication should be used like, for instance, Static-Static Diffie-Hellman when
   * both the originator and recipient public keys are bound to appropriate identities 
   * in X.509 certificates, see, for instance, {@link demo.cms.authenticatedData.AuthenticatedDataDemo
   * AuthenticatedDataDemo}.
   *
   * @param message the message to be authenticated, as byte representation
   * @param includeAuthAttrs whether to include authenticated attributes
   * @param mode the mode indicating whether to include the content 
   *        (AuthenticatedDataStream.IMPLICIT) or not (AuthenticatedDataStream.EXPLICIT)
   * @return the BER encoding of the <code>AuthenticatedData</code> object, wrapped in a ContentInfo
   * @exception CMSException if the <code>AuthenticatedData</code> object cannot
   *                         be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createAuthenticatedDataStream(byte[] message,
                                              boolean includeAuthAttrs,
                                              int mode)
    throws CMSException, IOException {
    
    AlgorithmID macAlgorithm = (AlgorithmID)AlgorithmID.hMAC_SHA1.clone();
    int macKeyLength = 64;
    AlgorithmID digestAlgorithm = null;
    // we need a digest algorithm if authenticated attributes shall be included
    if (includeAuthAttrs == true) {
      digestAlgorithm = (AlgorithmID)AlgorithmID.sha1.clone();
    }   
    ObjectID contentType = ObjectID.cms_data;
    
    AuthenticatedDataStream authenticatedData;

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);
    // create a new AuthenticatedData object 
    try {
      authenticatedData = new AuthenticatedDataStream(contentType,
                                                      is, 
                                                      macAlgorithm,
                                                      macKeyLength,
                                                      null,
                                                      digestAlgorithm,
                                                      mode);
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException(ex.toString());
    }

    // create the recipient infos
    RecipientInfo[] recipients = new RecipientInfo[2];
    // user1 is the first receiver
    recipients[0] = new KeyTransRecipientInfo(user1_crypt, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // user2 is the second receiver
    recipients[1] = new KeyTransRecipientInfo(user2_crypt, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // specify the recipients of the authenticated message
    authenticatedData.setRecipientInfos(recipients);
    
    if (includeAuthAttrs == true) {
       // create some autheticated attributes
       // (the message digest attribute is automatically added)
       try {
         Attribute[] attributes = { new Attribute(new CMSContentType(contentType)) };
         authenticatedData.setAuthenticatedAttributes(attributes);
       } catch (Exception ex) {
         throw new CMSException("Error creating attribute: " + ex.toString());   
       } 
    }    
    
    // in explicit mode get the content and write it  to any out-of-band place
    if (mode == AuthenticatedDataStream.EXPLICIT) {
      InputStream data_is = authenticatedData.getInputStream();
      byte[] buf = new byte[1024];
      int r;
      while ((r = data_is.read(buf)) > 0)
        ;   // skip data
    }    
    
    // create the ContentInfo
    ContentInfoStream cis = new ContentInfoStream(authenticatedData);
    // return the AuthenticatedData as encoded byte array with block size 2048
    ByteArrayOutputStream os = new ByteArrayOutputStream();

    cis.writeTo(os);
    return os.toByteArray();  
  }
  
  /**
   * Decrypts the encrypted MAC key for the recipient identified by its index
   * into the recipientInfos field and uses the MAC key to verify
   * the authenticated data.
   * <p>
   * This way of decrypting the MAC key and verifying the content may be used for 
   * any type of RecipientInfo (KeyTransRecipientInfo, KeyAgreeRecipientInfo, 
   * KEKRecipientInfo), but requires to know at what index of the recipientInfos
   * field the RecipientInfo for the particular recipient in mind can be found. 
   * If the recipient in mind uses a RecipientInfo of type KeyAgreeRecipientInfo
   * some processing overhead may take place because a KeyAgreeRecipientInfo may
   * contain encrypted mac keys for more than only one recipient; since the
   * recipientInfoIndex only specifies the RecipientInfo but not the encrypted
   * mac key -- if there are more than only one -- repeated decryption runs may be
   * required as long as the decryption process completes successfully.
   * <p>
   * <b>Attention:</b> This AuthenticatedData demo uses RSA as key management technique.
   * In practice (see RFC 5652) a key management technique that provides data origin
   * authentication should be used like, for instance, Static-Static Diffie-Hellman when
   * both the originator and recipient public keys are bound to appropriate identities 
   * in X.509 certificates, see, for instance, {@link demo.cms.authenticatedData.AuthenticatedDataDemo
   * AuthenticatedDataDemo}.
   *
   * @param encoding the BER encoded ContentInfo holding the <code>AuthenticatedData</code> object
   * @param message the content message, if transmitted by other means (explicit mode)
   * @param key the key to decrypt the mac key 
   * @param recipientInfoIndex the index of the right <code>RecipientInfo</code> to 
   *                           which the given key belongs
   *
   * @return the verified message, as byte array
   * @exception CMSException if the authenticated data cannot be verified
   * @exception IOException if a stream read/write error occurs
   */
  public byte[] getAuthenticatedDataStream(byte[] encoding, 
                                           byte[] message, 
                                           PrivateKey key, 
                                           int recipientInfoIndex)
    throws CMSException, IOException {

    // create the AuthenticatedData object from a DER encoded byte array
    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    // create the ContentInfo object
    ContentInfoStream cis = new ContentInfoStream(is);
    System.out.println("This ContentInfo holds content of type " + cis.getContentType().getName());
    AuthenticatedDataStream authenticatedData = (AuthenticatedDataStream)cis.getContent();
    
    if (authenticatedData.getMode() == AuthenticatedDataStream.EXPLICIT) {
      // in explicit mode explicitly supply the content for hash/mac computation  
      authenticatedData.setInputStream(new ByteArrayInputStream(message));
    }

    System.out.println("\nThis message can be verified by the following recipients:");
    RecipientInfo[] recipients = authenticatedData.getRecipientInfos();
    for (int i=0; i<recipients.length; i++) {
      System.out.println("Recipient "+(i+1)+":");
      System.out.println(recipients[i].getRecipientIdentifiers()[0]);
    }

    // decrypt the mac key and verify the mac for indented recipient
    try {
      authenticatedData.setupMac(key, recipientInfoIndex);
      InputStream contentStream = authenticatedData.getInputStream();
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      Util.copyStream(contentStream, os, null);
      
      if (authenticatedData.verifyMac() == false) {
        throw new CMSException("Mac verification error!");
      }  
      System.out.println("Mac successfully verified!");
      
      return os.toByteArray();

    } catch (InvalidKeyException ex) {
      throw new CMSException("Key error: "+ex.getMessage());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException(ex.toString());
    }
  }



  /**
   * Creates a CMS <code>Data</code> object.
   * <p>
   * @param message the message to be sent, as byte representation
   * @return the DER encoded ContentInfo holding the <code>Data</code> object just created
   * @exception CMSException if the <code>Data</code> object cannot
   *                          be created
   */
  public byte[] createData(byte[] message) throws CMSException  {

    System.out.println("Create a new Data message:");

    // create a new DigestedData object which includes the data
    Data data = new Data(message);
    ContentInfo ci = new ContentInfo(data);
    // return the ASN.1 representation
    return ci.toByteArray();
  }

  /**
   * Parses a CMS <code>Data</code> object.
   *
   * @param encoding the DER encoded ContentInfo holding with inherent <code>Data</code>
   *
   * @return the inherent message as byte array
   *
   * @exception CMSException if an parsing exception occurs
   * @exception if an I/O related error occurs
   */
  public byte[] getData(byte[] encoding) throws CMSException, IOException {
    
    ByteArrayInputStream encodedStream = new ByteArrayInputStream(encoding);
    // create the ContentInfo
    ContentInfo ci = new ContentInfo(encodedStream);
    System.out.println("This ContentInfo holds content of type " + ci.getContentType().getName());
    // create the Data object
    Data data = (Data)ci.getContent();
    
    // get and return the content
    return data.getData();
  }

  /**
   * Creates a CMS <code>EnvelopedData</code> message and wraps it into a ContentInfo.
   * <p>
   *
   * @param message the message to be enveloped, as byte representation
   * @return the DER encoded ContentInfo holding the EnvelopedData object just created
   * @exception CMSException if the <code>EnvelopedData</code> object cannot
   *                          be created
   */
  public byte[] createEnvelopedData(byte[] message) throws CMSException {

    EnvelopedData enveloped_data;

    // create a new EnvelopedData object encrypted with TripleDES CBC
    try {
      enveloped_data = new EnvelopedData(message, (AlgorithmID)AlgorithmID.des_EDE3_CBC.clone());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("No implementation for Triple-DES-CBC.");
    }

    // create the recipient infos
    RecipientInfo[] recipients = new RecipientInfo[2];
    // user1 is the first receiver
    recipients[0] = new KeyTransRecipientInfo(user1_crypt, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // user2 is the second receiver
    recipients[1] = new KeyTransRecipientInfo(user2_crypt, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // specify the recipients of the encrypted message
    enveloped_data.setRecipientInfos(recipients);
    
    // wrap into contentInfo
    ContentInfo ci = new ContentInfo(enveloped_data);
    // return the EnvelopedDate as DER encoded byte array
    return ci.toByteArray();
  }

  /**
   * Decrypts the encrypted content of the given <code>EnvelopedData</code> object for the
   * specified recipient and returns the decrypted (= original) message.
   *
   * @param encoding the DER encoded ContentInfo holding an EnvelopedData
   * @param privateKey the private key to decrypt the message
   * @param recipientInfoIndex the index into the <code>RecipientInfo</code> array
   *                           to which the specified private key belongs
   *
   * @return the recovered message, as byte array
   * @exception CMSException if the message cannot be recovered
   */
  public byte[] getEnvelopedData(byte[] encoding, PrivateKey privateKey, int recipientInfoIndex) throws CMSException, IOException {
    
    ByteArrayInputStream encodedStream = new ByteArrayInputStream(encoding);
    ContentInfo ci = new ContentInfo(encodedStream);
    EnvelopedData enveloped_data = (EnvelopedData)ci.getContent();

    System.out.println("Information about the encrypted data:");
    EncryptedContentInfo eci = (EncryptedContentInfo)enveloped_data.getEncryptedContentInfo();
    System.out.println("Content type: "+eci.getContentType().getName());
    System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());

    System.out.println("\nThis message can be decrypted by the owners of the following certificates:");
    RecipientInfo[] recipients = enveloped_data.getRecipientInfos();
    for (int i=0; i<recipients.length; i++) {
      System.out.println("Recipient "+(i+1)+":");
      System.out.println(recipients[i].getRecipientIdentifiers()[0]);
    }

    // decrypt the message
    try {
      enveloped_data.setupCipher(privateKey, recipientInfoIndex);
      return enveloped_data.getContent();

    } catch (InvalidKeyException ex) {
      throw new CMSException("Private key error: "+ex.toString());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.getMessage());
    }
  }

  /**
   * Creates a CMS <code>SignedData</code> object and wraps it into a ContentInfo.
   *
   * @param message the message to be signed, as byte representation
   * @param mode the mode indicating whether to include the content 
   *        (SignedDataStream.IMPLICIT) or not (SignedDataStream.EXPLICIT)
   * @return the DER encoded ContentInfo holding the <code>SignedData</code> object just created
   * @exception CMSException if the <code>SignedData</code> object cannot
   *                          be created
   */
  public byte[] createSignedData(byte[] message, int mode) throws CMSException  {

    System.out.println("Create a new message signed by user 1:");

    // create a new SignedData object which includes the data
    SignedData signed_data = new SignedData(message, mode);
    // SignedData shall include the certificate chain for verifying
    signed_data.setCertificates(certificates);

    // cert at index 0 is the user certificate
    IssuerAndSerialNumber issuer = new IssuerAndSerialNumber(user1_sign);

    // create a new SignerInfo
    SignerInfo signer_info = new SignerInfo(issuer, (AlgorithmID)AlgorithmID.sha1.clone(), user1_sign_pk);
    
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

      // another SignerInfo without authenticated attributes and RIPEMD-160 as hash algorithm
      signer_info = new SignerInfo(new IssuerAndSerialNumber(user2_sign),
          (AlgorithmID)AlgorithmID.ripeMd160.clone(), user2_sign_pk);
      // the message digest itself is protected
      signed_data.addSignerInfo(signer_info);

    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("No implementation for signature algorithm: "+ex.getMessage());
    }

    ContentInfo ci = new ContentInfo(signed_data);
    return ci.toByteArray();
  }

  /**
   * Parses a CMS <code>SignedData</code> object and verifies the signatures
   * for all participated signers.
   *
   * @param encoding the ContentInfo with inherent <code>SignedData</code> object, as DER encoding
   * @param message the the message which was transmitted out-of-band (explicit signed)
   *
   * @return the inherent message as byte array, or <code>null</code> if there
   *         is no message included into the supplied <code>SignedData</code>
   *         object
   * @exception CMSException if any signature does not verify
   * @exception IOException if an I/O error occurs
   */
  public byte[] getSignedData(byte[] encoding, byte[] message) throws CMSException, IOException {
    
    ByteArrayInputStream encodedStream = new ByteArrayInputStream(encoding);
    // create a content info from the ASN.1 object
    SignedData signed_data = new SignedData(encodedStream);
    
    if (signed_data.getMode() == SignedData.EXPLICIT) {
      // explicit mode: set content received by other means
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

    return signed_data.getContent();
  }


  
  /**
   * Creates a <i>SignedAndEncrypted</i> (i.e. sequential combination of <code>
   * SignedData</code> and <code>EnvelopedData</code>) object.
   *
   * @param message the message to be signed and encrypted, as byte representation
   * @return the DER encoded ContentInfo holding the signed and encrypted message object
   *         just created
   * @exception CMSException if the the <code>SignedData</code> or
   *                          <code>EnvelopedData</code> object cannot be created
   */
  public byte[] createSignedAndEncryptedData(byte[] message) throws CMSException {

    System.out.println("Create a new message signed by user1 encrypted for user2:");

    byte[] signed = createSignedData(message, SignedData.IMPLICIT);
    return createEnvelopedData(signed);
  }

  /**
   * Recovers the original message and verifies the signature.
   *
   * @param encoding the DER encoded ContentInfo holding a SignedAndEnryptedData object
   * @return the recovered message, as byte array
   * @exception CMSException if the message cannot be recovered
   * @exception IOException if an I/O error occurs
   */
  public byte[] getSignedAndEncryptedData(byte[] encoding) throws CMSException, IOException {
    
    // user2 means index 2 (hardcoded for this demo)
    byte[] signed = getEnvelopedData(encoding, user2_crypt_pk, 1);
    return getSignedData(signed, null);
  }


  /**
   * Creates a CMS <code>DigestedData</code> object.
   * <p>
   *
   * @param message the message to be digested, as byte representation
   * @return the <code>DigestedData</code> wrapped into a ContentInfo, as DER encoding
   * @exception CMSException if the <code>DigestedData</code> object cannot
   *                          be created
   */
  public byte[] createDigestedData(byte[] message, int mode) throws CMSException  {

    System.out.println("Create a new digested message:");

    // create a new DigestedData object which includes the data
    DigestedData digested_data = new DigestedData(message, (AlgorithmID)AlgorithmID.sha256.clone(), mode);
    ContentInfo ci = new ContentInfo(digested_data);
    return ci.toByteArray();
  }

  /**
   * Parses a CMS <code>DigestedData</code> object and verifies the hash value.
   *
   * @param encoding the ContentInfo holding a <code>DigestedData</code>, as DER encoding
   * @param message the the message which was transmitted out-of-band (explicit digested)
   *
   * @return the message
   * @exception CMSException if some parsing exception occurs
   * @exception IOException if an I/O error occurs
   */
  public byte[] getDigestedData(byte[] encoding, byte[] message) throws CMSException, IOException {
    
    ByteArrayInputStream encodedStream = new ByteArrayInputStream(encoding);
    // create a content info from the ASN.1 object
    ContentInfo ci = new ContentInfo(encodedStream);
    System.out.println("This ContentInfo holds content of type " + ci.getContentType().getName());

    DigestedData digested_data = new DigestedData(encodedStream);

    if (digested_data.getMode() == DigestedData.EXPLICIT) {
      // set content transmitted by other means
      digested_data.setContent(message);
    }

    // now verify the digest
    if (digested_data.verify()) {
      System.out.println("Hash ok!");
    } else {
      throw new CMSException("Hash verification failed!");
    }

    return digested_data.getContent();
  }


  /**
   * Creates a CMS <code>EncryptedData</code> message.
   * <p>
   * The supplied content is PBE-encrypted using the specified password.
   *
   * @param message the message to be encrypted, as byte representation
   * @param pbeAlgorithm the PBE algorithm to be used
   * @param password the password
   * @return the <code>EncryptedData</code> object wrapped into a ContentInfo, as DER encoding
   * @exception CMSException if the <code>EncryptedData</code> object cannot
   *                          be created
   */
  public byte[] createEncryptedData(byte[] message, AlgorithmID pbeAlgorithm, char[] password) throws CMSException {

    EncryptedData encrypted_data;

    try {
      encrypted_data = new EncryptedData(message);
      // encrypt the message
      encrypted_data.setupCipher(pbeAlgorithm, password);
    } catch (InvalidKeyException ex) {
      throw new CMSException("Key error: "+ex.toString());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.getMessage());
    }
    // create the ContentInfo
    ContentInfo ci = new ContentInfo(encrypted_data);
    return ci.toByteArray();

  }

  /**
   * Decrypts the PBE-encrypted content of the given <code>EncryptedData</code> object
   * using the specified password and returns the decrypted (= original) message.
   *
   * @param encoding the DER encoded ContentInfo holding the <code>EncryptedData</code> object
   * @param password the password to decrypt the message
   *
   * @return the recovered message, as byte array
   * @exception CMSException if the message cannot be recovered
   * @exception IOException if an I/O error occurs
   */
  public byte[] getEncryptedData(byte[] encoding, char[] password) throws CMSException, IOException {
    
    ByteArrayInputStream encodedStream = new ByteArrayInputStream(encoding);
    ContentInfo ci = new ContentInfo(encodedStream);
    System.out.println("This ContentInfo holds content of type " + ci.getContentType().getName());

    // get the EncryptedData
    EncryptedData encrypted_data = (EncryptedData)ci.getContent();

    System.out.println("Information about the encrypted data:");
    EncryptedContentInfo eci = (EncryptedContentInfo)encrypted_data.getEncryptedContentInfo();
    System.out.println("Content type: "+eci.getContentType().getName());
    System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());

    // decrypt the message
    try {
      encrypted_data.setupCipher(password);
      return encrypted_data.getContent();

    } catch (InvalidKeyException ex) {
      throw new CMSException("Key error: "+ex.toString());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.getMessage());
    } catch (InvalidAlgorithmParameterException ex) {
      throw new CMSException("Invalid Parameters: "+ex.toString());
    } catch (InvalidParameterSpecException ex) {
      throw new CMSException("Invalid Parameters: "+ex.toString());
    }
  }
  
  /**
   * Creates a CMS <code>AuthenticatedData</code> for the given message message.
   * <p>
   * <b>Attention:</b> This AuthenticatedData demo uses RSA as key management technique.
   * In practice (see RFC 5652) a key management technique that provides data origin
   * authentication should be used like, for instance, Static-Static Diffie-Hellman when
   * both the originator and recipient public keys are bound to appropriate identities 
   * in X.509 certificates, see, for instance, {@link demo.cms.authenticatedData.AuthenticatedDataDemo
   * AuthenticatedDataDemo}.
   *
   * @param message the message to be authenticated, as byte representation
   * @param includeAuthAttrs whether to include authenticated attributes
   * @param mode the mode indicating whether to include the content 
   *             (AuthenticatedData.IMPLICIT) or not (AuthenticatedDatam.EXPLICIT)
   * @return the BER encoding of the <code>AuthenticatedData</code> object, wrapped in a ContentInfo
   * @exception CMSException if the <code>AuthenticatedData</code> object cannot
   *                         be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createAuthenticatedData(byte[] message,
                                        boolean includeAuthAttrs,
                                        int mode)
    throws CMSException, IOException {
    
    AlgorithmID macAlgorithm = (AlgorithmID)AlgorithmID.hMAC_SHA1.clone();
    int macKeyLength = 64;
    AlgorithmID digestAlgorithm = null;
    // we need a digest algorithm if authenticated attributes shall be included
    if (includeAuthAttrs == true) {
      digestAlgorithm = (AlgorithmID)AlgorithmID.sha1.clone();
    }   
    ObjectID contentType = ObjectID.cms_data;
    
    AuthenticatedData authenticatedData;

    // create a new AuthenticatedData object 
    try {
      authenticatedData = new AuthenticatedData(contentType,
                                                message, 
                                                macAlgorithm,
                                                macKeyLength,
                                                null,
                                                digestAlgorithm,
                                                mode);
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException(ex.toString());
    }


    // create the recipient infos
    RecipientInfo[] recipients = new RecipientInfo[2];
    // user1 is the first receiver
    recipients[0] = new KeyTransRecipientInfo(user1_crypt, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // user2 is the second receiver
    recipients[1] = new KeyTransRecipientInfo(user2_crypt, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // specify the recipients of the authenticated message
    authenticatedData.setRecipientInfos(recipients);
    
    if (includeAuthAttrs == true) {
      // create some autheticated attributes
      // (the message digest attribute is automatically added)
      try {
        Attribute[] attributes = { new Attribute(new CMSContentType(contentType)) };
        authenticatedData.setAuthenticatedAttributes(attributes);
      } catch (Exception ex) {
        throw new CMSException("Error creating attribute: " + ex.toString());   
      } 
    }    
   
    // wrap the AuthenticatedData in a ContentInfo and encode it
    ContentInfo ci = new ContentInfo(authenticatedData);
    return ci.toByteArray();
  
  }
  
  /**
   * Decrypts the encrypted MAC key for the recipient identified by its index
   * into the recipientInfos field and uses the MAC key to verify
   * the authenticated data.
   * <p>
   * This way of decrypting the MAC key and verifying the content may be used for 
   * any type of RecipientInfo (KeyTransRecipientInfo, KeyAgreeRecipientInfo, 
   * KEKRecipientInfo), but requires to know at what index of the recipientInfos
   * field the RecipientInfo for the particular recipient in mind can be found. 
   * If the recipient in mind uses a RecipientInfo of type KeyAgreeRecipientInfo
   * some processing overhead may take place because a KeyAgreeRecipientInfo may
   * contain encrypted mac keys for more than only one recipient; since the
   * recipientInfoIndex only specifies the RecipientInfo but not the encrypted
   * mac key -- if there are more than only one -- repeated decryption runs may be
   * required as long as the decryption process completes successfully.
   * <p>
   * <b>Attention:</b> This AuthenticatedData demo uses RSA as key management technique.
   * In practice (see RFC 5652) a key management technique that provides data origin
   * authentication should be used like, for instance, Static-Static Diffie-Hellman when
   * both the originator and recipient public keys are bound to appropriate identities 
   * in X.509 certificates, see, for instance, {@link demo.cms.authenticatedData.AuthenticatedDataDemo
   * AuthenticatedDataDemo}.
   *
   * @param encoding the DER encoded ContentInfo holding the <code>AuthenticatedData</code> object
   * @param message the content message, if transmitted by other means (explicit mode)
   * @param key the key to decrypt the mac key
   * @param recipientInfoIndex the index of the right <code>RecipientInfo</code> to 
   *                           which the given key belongs
   *
   * @return the verified message, as byte array
   * @exception CMSException if the authenticated data cannot be verified
   * @exception IOException if a IO read/write error occurs
   */
  public byte[] getAuthenticatedData(byte[] encoding, 
                                     byte[] message,
                                     PrivateKey key,
                                     int recipientInfoIndex) 
    throws CMSException, IOException {
        
    // create the AuthenticatedData object from a DER encoded byte array
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    ContentInfo ci = new ContentInfo(is);
    System.out.println("This ContentInfo holds content of type " + ci.getContentType().getName());

    AuthenticatedData authenticatedData = (AuthenticatedData)ci.getContent();
    
    if (authenticatedData.getMode() == AuthenticatedData.EXPLICIT) {
      // in explicit mode explicitly supply the content for hash/mac computation  
      authenticatedData.setContent(message);
    }

    System.out.println("\nThis message can be verified by the following recipients:");
    RecipientInfo[] recipients = authenticatedData.getRecipientInfos();
    for (int i=0; i<recipients.length; i++) {
      System.out.println("Recipient "+(i+1)+":");
      System.out.println(recipients[i].getRecipientIdentifiers()[0]);
    }

    // decrypt the mac key and verify the mac for the first recipient
    try {
      authenticatedData.setupMac(key, recipientInfoIndex);
      if (authenticatedData.verifyMac() == false) {
        throw new CMSException("Mac verification error!");
      }  
      System.out.println("Mac successfully verified!");
      
      return authenticatedData.getContent();

    } catch (InvalidKeyException ex) {
      throw new CMSException("Key error: "+ex.getMessage());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException(ex.toString());
    }
  }




  /**
   * Tests the CMS content type implementations <code>Data</code>, <code>EnvelopedData</code>,
   * <code>SignedData</code>, <code>DigestedData</code>, <code>EncryptedData</code>.
   * An additional <i>SignedAndEncryptedData</i> test sequentially combines
   * signed and enveloped data.
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

      // the stream implementation
      //
      // test CMS DataStream
      //
      System.out.println("\nDataStream demo [create]:\n");
      encoding = createDataStream(message);
      // transmit data
      System.out.println("\nDataStream demo [parse]:\n");
      
      received_message = getDataStream(encoding);
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));


      // the stream implementation
      //
      // test CMS EnvelopedDataStream
      //
      System.out.println("\nEnvelopedDataStream demo [create]:\n");
      encoding = createEnvelopedDataStream(message);
      // transmit data
      System.out.println("\nEnvelopedDataStream demo [parse]:\n");
      // user1 means index 0 (hardcoded for this demo)
      received_message = getEnvelopedDataStream(encoding, user1_crypt_pk, 0);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(received_message));

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

      // test CMS SignedAndEncryptedDataStream
      //
      System.out.println("\nSignedAndEncryptedDataStream demo [create]:\n");
      encoding = createSignedAndEncryptedDataStream(message);
      // transmit data
      System.out.println("\nSignedAndEncryptedDataStream demo [parse]:\n");
      received_message = getSignedAndEncryptedDataStream(encoding);
      System.out.print("\nSignedAndEncrypted content: ");
      System.out.println(new String(received_message));


      //
      // test CMS Implicit DigestedDataStream
      //
      System.out.println("\nImplicit DigestedDataStream demo [create]:\n");
      encoding = createDigestedDataStream(message, DigestedDataStream.IMPLICIT);
      // transmit data
      System.out.println("\nImplicit DigestedDataStream demo [parse]:\n");
      received_message = getDigestedDataStream(encoding, null);
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));

      //
      // test CMS Explicit DigestedDataStream
      //
      System.out.println("\nExplicit DigestedDataStream demo [create]:\n");
      encoding = createDigestedDataStream(message, DigestedDataStream.EXPLICIT);
      // transmit data
      System.out.println("\nExplicit DigestedDataStream demo [parse]:\n");
      received_message = getDigestedDataStream(encoding, message);
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));

      //
      // test CMS EncryptedDataStream
      //
      System.out.println("\nEncryptedDataStream demo [create]:\n");
      encoding = createEncryptedDataStream(message, (AlgorithmID)AlgorithmID.pbeWithSHAAnd3_KeyTripleDES_CBC.clone(), "password".toCharArray());
      // transmit data
      System.out.println("\nEncryptedDataStream demo [parse]:\n");
      received_message = getEncryptedDataStream(encoding, "password".toCharArray());
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));
      
            
      //
      // test CMS Implicit AuthenticatedDataStream with auth attributes
      //
      System.out.println("\nImplicit AuthenticatedDataStream demo with auth attributes [create]:\n");
      encoding = createAuthenticatedDataStream(message, true, AuthenticatedDataStream.IMPLICIT);
      // transmit data
      System.out.println("\nImplicit AuthenticatedDataStream demo with auth attributes [parse]:\n");
      received_message = getAuthenticatedDataStream(encoding, null, user1_crypt_pk, 0);
      System.out.print("\nVerified content: ");
      System.out.println(new String(received_message));
      
      System.out.println("\nImplicit AuthenticatedDataStream demo without auth attributes [create]:\n");
      encoding = createAuthenticatedDataStream(message, false, AuthenticatedDataStream.IMPLICIT);
      // transmit data
      System.out.println("\nImplicit AuthenticatedDataStream demo without auth attributes [parse]:\n");
      received_message = getAuthenticatedDataStream(encoding, null, user1_crypt_pk, 0);
      System.out.print("\nVerified content: ");
      System.out.println(new String(received_message));

      //
      // test CMS Explicit AuthenticatedDataStream
      //
      System.out.println("\nExplicit AuthenticatedDataStream demo with auth attributes [create]:\n");
      encoding = createAuthenticatedDataStream(message, true, AuthenticatedDataStream.EXPLICIT);
      // transmit data
      System.out.println("\nExplicit AuthenticatedDataStream demo with auth attributes [parse]:\n");
      received_message = getAuthenticatedDataStream(encoding, message, user1_crypt_pk, 0);
      System.out.print("\nVerified content: ");
      System.out.println(new String(received_message));
      
      System.out.println("\nExplicit AuthenticatedDataStream demo without auth attributes [create]:\n");
      encoding = createAuthenticatedDataStream(message, false, AuthenticatedDataStream.EXPLICIT);
      // transmit data
      System.out.println("\nExplicit AuthenticatedDataStream demo with auth attributes [parse]:\n");
      received_message = getAuthenticatedDataStream(encoding, message, user1_crypt_pk, 0);
      System.out.print("\nVerified content: ");
      System.out.println(new String(received_message));


      // the non-stream implementation
      System.out.println("\nNon-stream implementation demos");
      System.out.println("===============================");
      
      //
      // test CMS Data
      //
      System.out.println("\nData demo [create]:\n");
      encoding = createData(message);
      // transmit data
      System.out.println("\nData demo [parse]:\n");

      received_message = getData(encoding);
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));

      //
      // test CMS EnvelopedData
      //
      System.out.println("\nEnvelopedData demo [create]:\n");
      encoding = createEnvelopedData(message);
      // transmit data
      System.out.println("\nEnvelopedData demo [parse]:\n");
      // user1 means index 0 (hardcoded for this demo)
      received_message = getEnvelopedData(encoding, user1_crypt_pk, 0);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(received_message));

      //
      // test CMS Implicit SignedData
      //
      System.out.println("\nImplicit SignedData demo [create]:\n");
      encoding = createSignedData(message, SignedDataStream.IMPLICIT);
      // transmit data
      System.out.println("\nImplicit SignedData demo [parse]:\n");
      received_message = getSignedData(encoding, null);
      System.out.print("\nSigned content: ");
      System.out.println(new String(received_message));

      //
      // test CMS Explicit SignedData
      //
      System.out.println("\nExplicit SignedData demo [create]:\n");
      encoding = createSignedData(message, SignedData.EXPLICIT);
      // transmit data
      System.out.println("\nExplicit SignedData demo [parse]:\n");
      received_message = getSignedData(encoding, message);
      System.out.print("\nSigned content: ");
      System.out.println(new String(received_message));

      //
      // test CMS SignedAndEncryptedData
      //
      System.out.println("\nSignedAndEncryptedData demo [create]:\n");
      encoding = createSignedAndEncryptedData(message);
      // transmit data
      System.out.println("\nSignedAndEncryptedData demo [parse]:\n");
      received_message = getSignedAndEncryptedData(encoding);
      System.out.print("\nSignedAndEncrypted content: ");
      System.out.println(new String(received_message));


      //
      // test CMS Implicit DigestedData
      //
      System.out.println("\nImplicit DigestedData demo [create]:\n");
      encoding = createDigestedData(message, DigestedData.IMPLICIT);
      // transmit data
      System.out.println("\nImplicit DigestedData demo [parse]:\n");
      received_message = getDigestedData(encoding, null);
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));

      //
      // test CMS Explicit DigestedData
      //
      System.out.println("\nExplicit DigestedData demo [create]:\n");
      encoding = createDigestedData(message, DigestedData.EXPLICIT);
      // transmit data
      System.out.println("\nExplicit DigestedData demo [parse]:\n");
      received_message = getDigestedData(encoding, message);
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));

      //
      // test CMS EncryptedData
      //
      System.out.println("\nEncryptedData demo [create]:\n");
      encoding = createEncryptedData(message, (AlgorithmID)AlgorithmID.pbeWithSHAAnd3_KeyTripleDES_CBC.clone(), "password".toCharArray());
      // transmit data
      System.out.println("\nEncryptedData demo [parse]:\n");
      received_message = getEncryptedData(encoding, "password".toCharArray());
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));
      
          //
      // test CMS Implicit AuthenticatedData 
      //
      System.out.println("\nImplicit AuthenticatedData demo with auth attributes [create]:\n");
      encoding = createAuthenticatedData(message, true, AuthenticatedData.IMPLICIT);
      // transmit data
      System.out.println("\nImplicit AuthenticatedData demo with auth attributes [parse]:\n");
      received_message = getAuthenticatedData(encoding, null, user1_crypt_pk, 0);
      System.out.print("\nVerified content: ");
      System.out.println(new String(received_message));
      
      System.out.println("\nImplicit AuthenticatedData demo without auth attributes [create]:\n");
      encoding = createAuthenticatedData(message, false, AuthenticatedData.IMPLICIT);
      // transmit data
      System.out.println("\nImplicit AuthenticatedData demo without auth attributes [parse]:\n");
      received_message = getAuthenticatedData(encoding, null, user1_crypt_pk, 0);
      System.out.print("\nVerified content: ");
      System.out.println(new String(received_message));

      //
      // test CMS Explicit AuthenticatedData
      //
      System.out.println("\nExplicit AuthenticatedData demo with auth attributes [create]:\n");
      encoding = createAuthenticatedData(message, true, AuthenticatedData.EXPLICIT);
      // transmit data
      System.out.println("\nExplicit AuthenticatedData demo with auth attributes [parse]:\n");
      received_message = getAuthenticatedData(encoding, message, user1_crypt_pk, 0);
      System.out.print("\nVerified content: ");
      System.out.println(new String(received_message));
      
      System.out.println("\nExplicit AuthenticatedData demo without auth attributes [create]:\n");
      encoding = createAuthenticatedData(message, false, AuthenticatedData.EXPLICIT);
      // transmit data
      System.out.println("\nExplicit AuthenticatedData demo with auth attributes [parse]:\n");
      received_message = getAuthenticatedData(encoding, message, user1_crypt_pk, 0);
      System.out.print("\nVerified content: ");
      System.out.println(new String(received_message));


      System.out.println("Ready!");

   	} catch (Exception ex) {
   	  ex.printStackTrace();
   	  throw new RuntimeException(ex.toString());
   	}
  }


  /**
   * Starts the CMS content type implementation tests.
   *
   * @exception Exception
   *            if some error occurs 
   */
  public static void main(String argv[]) throws Exception {

   	demo.DemoUtil.initDemos();

    (new CMSDemo()).start();

    DemoUtil.waitKey();
  }
}
