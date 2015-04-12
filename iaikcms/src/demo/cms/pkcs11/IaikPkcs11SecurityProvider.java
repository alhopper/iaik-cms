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
// $Header: /IAIK-CMS/current/src/demo/cms/pkcs11/IaikPkcs11SecurityProvider.java 5     8.11.13 17:12 Dbratko $
//

package demo.cms.pkcs11;

import iaik.asn1.structures.AlgorithmID;
import iaik.cms.CMSAlgorithmID;
import iaik.cms.DigestInfo;
import iaik.cms.IaikProvider;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.keys.IAIKPKCS11Key;
import iaik.pkcs.pkcs11.provider.keys.IAIKPKCS11PrivateKey;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;



/**
 * This class implements a <code>SecurityProvider</code> for the IAIK-CMS
 * toolkit. This <code>SecurityProvider</code> can handle
 * <code>IAIKPKCS11Key</code> objects and is thus suitable for use with the
 * PKCS#11 provider. The demos in this package use this class to get the
 * IAIK-CMS library to use a PKCS#11 module instead of pure software crypto.
 * <p>
 * To install this security provider call:
 * <pre>
 * IAIKPkcs11 iaikPkcs11Provider = ...;
 * IaikPkcs11SecurityProvider pkcs11CmsSecurityProvider = new IaikPkcs11SecurityProvider(iaikPkcs11Provider);
 * SecurityProvider.setSecurityProvider(pkcs11CmsSecurityProvider);
 * </pre>
 *
 * @author Dieter Bratko
 */
public class IaikPkcs11SecurityProvider extends IaikProvider {

  /**
   * Switch on/off debug output.
   */
  private final static boolean DEBUG = true;

  /**
   * The name of the security provider.
   */
  private final static String PROVIDER_NAME = "IAIK PKCS#11 Security Provider";

  /**
   * Reference to the installed PKCS#11 provider instance.
   */
  protected IAIKPkcs11 iaikPkcs11Provider_;

  /**
   * The given PKCS#11 provider instance must already be installed in the JCA 
   * framework.
   * 
   * @param iaikPkcs11Provider The PKCS#11 provider instance to use in this CMS
   *                           security provider. 
   */
  public IaikPkcs11SecurityProvider(IAIKPkcs11 iaikPkcs11Provider) {
    super();
    // providerName_ = PROVIDER_NAME;
    iaikPkcs11Provider_ = iaikPkcs11Provider;
  }

  /**
   * Calculates the signature value for a CMS SignerInfo over the given digest
   * value with the given algorithm using the supplied private key.
   * <p>
   * Each {@link iaik.cms.SignerInfo SignerInfo} included in a CMS SignedData
   * object may calculate the signature value differently depending on the
   * presence of signed attributes:
   * <p>
   * <ul>
   * <li>If signed attributes are present the signature is calculated over
   *     the DER encoding of the signed attributes.
   * <li>If signed attributes are NOT present, the signature is calculated
   *     over the content data itsself.
   * </ul>
   * This method is called by class {@link iaik.cms.SignerInfo SignerInfo} for
   * calculating the signature when no signed attributes are present. Since
   * the data to be signed may be of arbitrary size this method expects the
   * already hashed data to only calculate the signature value on it (for
   * instance, by doing the digest encrypting when using RSA for signing).
   * <p>
   * For that reason, when writing your own SecurityProvider and overriding
   * this method, you will need some kind of <i>RAW</i> signature (respectively
   * digest encryption) mechanism only expecting the already hashed data (e.g.
   * a "RawDSA" signature engine when using DSA repectively a Cipher engine
   * when using RSA).
   * <p>
   * If you want to override this method for use with smartcards, please be sure
   * that your smartcard is able to do the signature (respectively digest
   * encryption) operation only. However, if your smartcard requires to supply
   * the whole data for doing the hash calcualtion itself, you may ensure that
   * your {@link iaik.cms.SignerInfo SignerInfo} contains signed attributes
   * and override method {@link #calculateSignatureFromSignedAttributes
   * calculateSignatureFromSignedAttributes} for calculating the signature over
   * the DER encoding of the signed attributes (thereby doing the hash
   * computation, too).
   *
   * @param signatureAlgorithm signatureAlgorithm the signature algorithm to be
   *        used, e.g. rsaEncryption, DSA
   * @param digestAlgorithm the digest algorithm used for hash computation (e.g.
   *        SHA-1 or MD5); may be necessary for some signature schemes (e.g.
   *        to be included as a DigestInfo in a PKCS#1 RSA signature)
   * @param privateKey the private key of the signer (i.e. the one supplied when
   *        creating a {@link iaik.cms.SignerInfo SignerInfo} object; may be
   *        some kind of "dummy" key when used for smartcards
   * @param digest the digest value over which the signature shall be calculated
   *
   * @return the signature value calculated from the given digest value
   *
   * @exception NoSuchAlgorithmException if any of the required algorithms is not supported
   * @exception InvalidKeyException if the key is not valid
   * @exception SignatureException if signature verification fails because of some crypto related error
   */
  public byte[] calculateSignatureFromHash(AlgorithmID signatureAlgorithm,
    AlgorithmID digestAlgorithm, PrivateKey privateKey, byte[] digest)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
  {
    byte[] signatureValue;

    // we handle PKCS#11 keys in a special way, but we forward other keys to the default implementation
    if (privateKey instanceof IAIKPKCS11PrivateKey) {
      IAIKPkcs11 iaikPkcs11KeyProvider = ((IAIKPKCS11PrivateKey) privateKey).getTokenManager().getProvider();

      String algorithmName = privateKey.getAlgorithm();

      Signature signatureEngine;
      byte[] dataToBeSigned = digest;
      try {
        if (algorithmName.equals("RSA")) {
          if (signatureAlgorithm.equals(CMSAlgorithmID.rsassaPss)) {   
            signatureEngine = Signature.getInstance("RawRSA/PSS", iaikPkcs11KeyProvider.getName());
          } else {
            DigestInfo digestInfo = new DigestInfo(digestAlgorithm, digest);
            dataToBeSigned = digestInfo.toByteArray();
            signatureEngine = Signature.getInstance("RawRSA/PKCS1", iaikPkcs11KeyProvider.getName());
          }  
        } else if (algorithmName.equals("DSA")) {
          signatureEngine = Signature.getInstance("RawDSA", iaikPkcs11KeyProvider.getName());
        } else if ((algorithmName.equals("EC")) || (algorithmName.equals("ECDSA"))) {
          signatureEngine = Signature.getInstance("RawECDSA", iaikPkcs11KeyProvider.getName());
        } else {
          throw new NoSuchAlgorithmException(
            "Unable to calculate signature with signature algorithm: " + signatureAlgorithm);
        }
        
      } catch (NoSuchProviderException ex) {
        throw new NoSuchAlgorithmException("The PKCS#11 provider has not been installed corerctly: " + ex);
      }
      signatureEngine.initSign(privateKey);
      signatureEngine.update(dataToBeSigned);
      signatureValue = signatureEngine.sign();
    } else {
      signatureValue = super.calculateSignatureFromHash(signatureAlgorithm, digestAlgorithm, privateKey, digest);
    }

    return signatureValue ;
  }
  
  /**
   * Calculates the signature value for a CMS SignerInfo over the given signed 
   * attributes with the given algorithm using the supplied private key.
   * <p>
   * Each {@link iaik.cms.SignerInfo SignerInfo} included in a CMS SignedData
   * object may calculate the signature value differently depending on the
   * presence of signed attributes:
   * <p>
   * <ul>
   * <li>If signed attributes are present the signature is calculated over
   *     the DER encoding of the signed attributes. 
   * <li>If signed attributes are NOT present, the signature is calculated
   *     over the content data itsself.
   * </ul>
   * This method is called by class {@link iaik.cms.SignerInfo SignerInfo} for
   * calculating the signature when signed attributes are present. 
   * <p>
   * When writing your own SecurityProvider and overriding
   * this method, be aware that only the -- yet NOT hashed -- DER encoding of
   * the signed attributes is supplied to this method. For that reason this
   * method can be overriden for use with smartcards requiring to do the 
   * digest calculation theirselves: ensure that your {@link iaik.cms.SignerInfo
   * SignerInfo} contains signed attributes and override this method in a way
   * to pass the given DER encoding of the signed attributes to your smartcard
   * for doing the signature (and digest) calculation.
   * <p>
   * Since this method requires to calculate the digest value over the DER encoded
   * signed attributes as part of the signature calculation, it uses a 
   * ordinary JCA Signature engine.
   *
   * @param signatureAlgorithm signatureAlgorithm the signature algorithm to be
   *        used, e.g. rsaEncryption, DSA
   * @param digestAlgorithm the digest algorithm to be used for hash computation (e.g.
   *        SHA-1,..., SHA-512); may be necessary for some signature schemes (e.g.
   *        to be included as a DigestInfo in a PKCS#1 RSA signature)
   * @param privateKey the private key of the signer (i.e. the one supplied when
   *        creating a {@link iaik.cms.SignerInfo SignerInfo} object; may be
   *        some kind of "dummy" key when used for smartcards
   * @param signedAttributes the DER encoding of the signed attributes over which 
   *        the signature shall be calculated
   *
   * @return the signature value calculated from the given DER encoded signed
   *         attributes
   *
   * @exception NoSuchAlgorithmException if no Signature engine is available for the requested algorithm
   * @exception InvalidKeyException if the key is not valid
   * @exception if signature calculation fails
   */
  public byte[] calculateSignatureFromSignedAttributes(AlgorithmID signatureAlgorithm, 
    AlgorithmID digestAlgorithm, PrivateKey privateKey, byte[] signedAttributes) 
    throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
      
    byte[] digest = getHash(digestAlgorithm, signedAttributes);
    return calculateSignatureFromHash(signatureAlgorithm, digestAlgorithm, privateKey, digest);

  }  

  /**
   * This method returns the desired Signature object which uses the PKCS#11
   * provider if the key is a PKCS#11 key.
   *
   * If the mode parameter is <CODE>SIGNATURE_SIGN</CODE> or 
   * <CODE>SIGNATURE_VERIFY</CODE> the signature object has to be
   * initialized with the provided key in the respective mode.
   *
   * @param algorithm the name of the Signature algorithm
   * @param mode the mode indicating if the engine has to be initialized
   * @param key the key for initializing the Signature engine
   *
   * @return the (if requested initialized) Signature engine
   *
   * @exception InvalidKeyException if the key is not valid 
   * @exception NoSuchAlgorithmException if no Signature engine is
   *            available for the requested algorithm
   */
  public Signature getSignature(String algorithm, int mode, Key key) 
    throws InvalidKeyException, NoSuchAlgorithmException {
        
    Signature signature;
    
    // for PKCS#11 keys we use the PKCS#11 provider, for other keys we use the default implementation
    if (key instanceof IAIKPKCS11Key) {
      try {
        signature = Signature.getInstance(algorithm, iaikPkcs11Provider_.getName());
      } catch (NoSuchProviderException e) {
        throw new NoSuchAlgorithmException("PKCS#11 Provider has not been installed correctly " + e.toString());
      }  
      if (mode == SIGNATURE_SIGN) {
        signature.initSign((PrivateKey)key);
      } else if (mode == SIGNATURE_VERIFY) {
        signature.initVerify((PublicKey)key);
      } // do nothing for SIGNATURE_NONE
    } else {
      signature = super.getSignature(algorithm, mode, key);  
    }
    
    return signature ;
  }
  
  /**
   * This method returns the desired Signature object.
   *
   * If the mode parameter is <CODE>SIGNATURE_SIGN</CODE> or 
   * <CODE>SIGNATURE_VERIFY</CODE> the signature object is to be
   * initialized with the provided key in the respective mode.
   * If algorithm parameters are specified they are set for the
   * Signature engine.
   *
   * @param algorithm the AlgorithmID of the Signature algorithm
   * @param mode the mode indicating if the engine has to be initialized
   * @param key the key for initializing the Signature engine
   * @param paramSpec any parameters to be set for the Signature engine, if not <code>null</code>
   *
   * @return the (if requested initialized) Signature engine
   *
   * @exception InvalidKeyException if the key is not valid 
   * @exception NoSuchAlgorithmException if no Signature engine is
   *            available for the requested algorithm
   */
  public Signature getSignature(AlgorithmID algorithm, 
                                int mode, 
                                Key key,
                                AlgorithmParameterSpec paramSpec) 
   throws InvalidKeyException, NoSuchAlgorithmException {
    
    Signature signature;
    
    // for PKCS#11 keys we use the PKCS#11 provider, for other keys we use the default implementation
    if (key instanceof IAIKPKCS11Key) {
     
      signature = algorithm.getSignatureInstance(iaikPkcs11Provider_.getName());
        
      if (mode == SIGNATURE_SIGN) {
        signature.initSign((PrivateKey)key);
      } else if (mode == SIGNATURE_VERIFY) {
        signature.initVerify((PublicKey)key);
      } // do nothing for SIGNATURE_NONE
    } else {
      signature = super.getSignature(algorithm, mode, key, paramSpec);  
    }
    if (paramSpec != null) {
      setSignatureParameters(signature, paramSpec);
    }
    return signature ;
    
  }
 
  /**
   * Decrypts the given encrypted content encryption key for a {@link 
   * iaik.cms.KeyTransRecipientInfo KeyTransRecipientInfo}.
   * <p>
   * CMS <code>EnvelopedData</code> uses the {@link 
   * iaik.cms.KeyTransRecipientInfo KeyTransRecipientInfo} type for
   * encrypting the secret content encryption key with the public key of
   * the recipient. Currently in general RSA PKCS#1v1.5 is used for key
   * transport. If rsaEncryption is requested as key encryption algorithm
   * this method uses a RSA Cipher ("RSA/ECB/PKCS1Padding/Encrypt") for
   * decrypting the encrypted content encryption key with the supplied 
   * private key of the recipient. If another algorithm than RSA is requested,
   * this method throws a NoSuchAlgorithmException. An application wishing to
   * support another algorithm may override this method.
   *
   * @param encryptedKey the encrypted content encryption key to be decrypted
   * @param kea the key encryption alglorithm to be used, e.g. rsaEncryption
   * @param recipientKey the private key of the recipient to be used for decrypting
   *                     the encrypted content encryption key
   * @param cekAlgorithmName the name of the content encryption key (e.g. "DES") to be set for the
   *                         SecretKey object created by this method
   *
   * @return the decrypted content encryption key
   *
   * @exception NoSuchAlgorithmException if the requested algorithm is not available
   * @exception InvalidKeyException if the decryption key is not valid
   * @exception NoSuchPaddingException if the required padding scheme is not supported
   * @exception BadPaddingException if an padding error occurs
   */
  public SecretKey decryptKey(byte[] encryptedKey, AlgorithmID kea, PrivateKey recipientKey, String cekAlgorithmName) 
    throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException 
  {
    SecretKey decryptedSymmetricKey;

    // we handle PKCS#11 keys in a special way, but we forward other keys to the default implementation
    if (recipientKey instanceof IAIKPKCS11PrivateKey) {
      IAIKPkcs11 iaikPkcs11KeyProvider = ((IAIKPKCS11PrivateKey) recipientKey).getTokenManager().getProvider();
      String algorithmImplementationName = kea.getImplementationName();

      try {
        Cipher cipher = Cipher.getInstance(algorithmImplementationName, iaikPkcs11KeyProvider.getName());
        cipher.init(Cipher.DECRYPT_MODE, recipientKey, (AlgorithmParameterSpec) null, (SecureRandom) null);
        byte[] cek = cipher.doFinal(encryptedKey);
        decryptedSymmetricKey = new iaik.security.cipher.SecretKey(cek, cekAlgorithmName);
        
      } catch (NoSuchProviderException ex) {
        throw new NoSuchAlgorithmException("The PKCS#11 provider has not been installed corerctly: " + ex);
      } catch (InvalidAlgorithmParameterException ex) {
        throw new NoSuchAlgorithmException("Error initializing the cipher: " + ex);
      } catch (IllegalBlockSizeException ex) {
        throw new NoSuchAlgorithmException("Error during cipher operation: " + ex);
      }
    } else {
      decryptedSymmetricKey = super.decryptKey(encryptedKey, kea, recipientKey, cekAlgorithmName);
    }

    return decryptedSymmetricKey ;
  }

  /**
   * Decrypts the given encrypted content encryption key for a {@link 
   * iaik.cms.KeyTransRecipientInfo KeyTransRecipientInfo}.
   * <p>
   * CMS <code>EnvelopedData</code> uses the {@link 
   * iaik.cms.KeyTransRecipientInfo KeyTransRecipientInfo} type for
   * encrypting the secret content encryption key with the public key of
   * the recipient. Currently in general RSA PKCS#1v1.5 is used for key
   * transport. If rsaEncryption is requested as key encryption algorithm
   * this method uses a RSA Cipher ("RSA/ECB/PKCS1Padding/Encrypt") for
   * decrypting the encrypted content encryption key with the supplied 
   * private key of the recipient. If another algorithm than RSA is requested,
   * this method throws a NoSuchAlgorithmException. An application wishing to
   * support another algorithm may override this method.
   *
   * @param encryptedKey the encrypted content encryption key to be decrypted
   * @param kea the key encryption alglorithm to be used, e.g. rsaEncryption
   * @param recipientKey the private key of the recipient to be used for decrypting
   *                     the encrypted content encryption key
   *
   * @return the decrypted content encryption key, the algorithm name will be set to "RAW"
   *
   * @exception NoSuchAlgorithmException if the requested algorithm is not available
   * @exception InvalidKeyException if the decryption key is not valid
   * @exception NoSuchPaddingException if the required padding scheme is not supported
   * @exception BadPaddingException if an padding error occurs
   */
// only needed for old CMS versions
//  public SecretKey decryptKey(byte[] encryptedKey, AlgorithmID kea, PrivateKey recipientKey) 
//    throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException 
//  {
//    return decryptKey(encryptedKey, kea, recipientKey, "RAW"); 
//  }
    
}
