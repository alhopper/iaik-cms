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
// $Header: /IAIK-CMS/current/src/demo/cms/ecc/keystore/SetupCMSEccKeyStore.java 16    9.07.13 14:22 Dbratko $
// $Revision: 16 $
//

package demo.cms.ecc.keystore;

import iaik.asn1.CodingException;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.GeneralName;
import iaik.asn1.structures.GeneralNames;
import iaik.asn1.structures.Name;
import iaik.asn1.structures.PolicyInformation;
import iaik.asn1.structures.PolicyQualifierInfo;
import iaik.cms.CMSAlgorithmID;
import iaik.x509.SimpleChainVerifier;
import iaik.x509.X509Certificate;
import iaik.x509.X509ExtensionException;
import iaik.x509.extensions.AuthorityKeyIdentifier;
import iaik.x509.extensions.BasicConstraints;
import iaik.x509.extensions.CertificatePolicies;
import iaik.x509.extensions.KeyUsage;
import iaik.x509.extensions.SubjectAltName;
import iaik.x509.extensions.SubjectKeyIdentifier;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Random;

import demo.DemoUtil;
import demo.cms.ecc.ECCDemoUtil;

/**
 * Creates a test KeyStore ("cmsecc.keystore") in the current working directory.
 * These keys are used by the ECC demos included in IAIK-CMS.
 * The aliases and the password for accessing the keys and
 * certificates can be found in {@link CMSEccKeyStoreConstants
 * CMSEccKeyStoreConstants}.
 *
 * @see CMSEccKeyStoreConstants
 * @see CMSEccKeyStore
 *
 */
public class SetupCMSEccKeyStore implements CMSEccKeyStoreConstants {

  // the key length of the CA certificate 
  private final static int CA_KEYLENGTH = 256;

  // the key store to create
  KeyStore key_store;
  // the file where the key store shall be saved
  String keystore_file;
  // takes the existing keys from the KeyStore and only creates new certificates
  boolean create_only_certificates = true;

  KeyPair ca_ecdsa = null;
  KeyPair ecdsa192 = null;
  KeyPair ecdsa224 = null;
  KeyPair ecdsa256 = null;
  KeyPair ecdsa384 = null;
  KeyPair ecdsa521 = null;
  KeyPair ecdh192 = null;
  KeyPair ecdh192_ = null;
  KeyPair ecdh256 = null;
  KeyPair ecdh256_ = null;
  KeyPair ecdh384 = null;
  KeyPair ecdh384_ = null;
  KeyPair ecdh521 = null;
  KeyPair ecdh521_ = null;

  // create ECDSA keys and certificates
  boolean create_ecdsa;
  // create ECDH keys and certificates
  boolean create_ecdh;
  
  
  /**
   * Default Constructor.
   */
  public SetupCMSEccKeyStore() {
    create_ecdsa = true;
    create_ecdh = true;
  }  

  /**
   * Generates a key pair for a curve with a certain name
   * 
   * @param bitLength the length of the key (in bits).
   * 
   * @return the generated key pair
   * 
   * @exception NoSuchAlgorithmException if ECDSA KeyPairGenerator is not available
   * @exception NoSuchProviderException if provider IAIK_ECC is not installed
   * @exception InvalidAlgorithmParameterException if the KeyPair cannot be generated becuase the 
   *                                               the requested curve is not supported
   */
  public KeyPair generateKeyPair(int bitLength)
    throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
    String providerName = "IAIK ECCelerate";
    if (Security.getProvider(providerName) == null) {
      providerName = "IAIK_ECC";
    }
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", providerName);
    kpg.initialize(bitLength);
    return kpg.generateKeyPair();
    
  }
  
  /**
   * Creates a certificate from the given values.
   *
   * @param subject the subject of the certificate
   * @param publicKey the public key to include
   * @param issuer the issuer of the certificate
   * @param privateKey the private key for signing the certificate
   * @param algorithm the signature algorithm to use
   * @param keyID the key id for the AuthotityKeyIdentifier extension
   * @param forSigning if the certificate to be created shall be used for signing or encryption
   *
   * @return the certificate just created
   */
  public static X509Certificate createCertificate(Name subject, PublicKey publicKey, 
      Name issuer, PrivateKey privateKey, AlgorithmID algorithm, byte[] keyID, boolean forSigning) {

    // create a new certificate
    X509Certificate cert = new X509Certificate();

    try {
      // set the values
      cert.setSerialNumber(new BigInteger(20, new Random()));
      cert.setSubjectDN(subject);
      cert.setPublicKey(publicKey);
      cert.setIssuerDN(issuer);

      GregorianCalendar date = new GregorianCalendar();
      // not before now
      cert.setValidNotBefore(date.getTime());

      if (issuer.equals(subject)) {
        // ca certificate
        date.add(Calendar.YEAR, 5);  
        BasicConstraints basicConstraints = new BasicConstraints(true);
        cert.addExtension(basicConstraints);
        KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        cert.addExtension(keyUsage);
      } else { 
        // end user certificate
        date.add(Calendar.YEAR, 6);  
        KeyUsage keyUsage = null;
        if (forSigning) {
          keyUsage = new KeyUsage(KeyUsage.digitalSignature |
                                  KeyUsage.nonRepudiation);
        } else {                  
            keyUsage = new KeyUsage(KeyUsage.keyEncipherment |
                                    KeyUsage.dataEncipherment |
                                    KeyUsage.keyAgreement) ; 
        }                          
        cert.addExtension(keyUsage);
        AuthorityKeyIdentifier authID = new AuthorityKeyIdentifier();
        authID.setKeyIdentifier(keyID);
        cert.addExtension(authID);
        GeneralNames generalNames = new GeneralNames();
        generalNames.addName(new GeneralName(GeneralName.rfc822Name, "smimetest@iaik.tugraz.at"));
        SubjectAltName subjectAltName = new SubjectAltName(generalNames);
        cert.addExtension(subjectAltName);
      }
      String explicitText = "This certificate only may be used for test purposes";
      PolicyQualifierInfo policyQualifier = new PolicyQualifierInfo(null, null, explicitText);
      PolicyInformation[] policyInformations = 
        { new PolicyInformation(new ObjectID("1.3.6.1.4.1.2706.2.2.4.1.1.1.1"),
                              new PolicyQualifierInfo[] { policyQualifier }) };
      CertificatePolicies certPolicies = new CertificatePolicies(policyInformations);                        
      
      SubjectKeyIdentifier subjectKeyID = new SubjectKeyIdentifier(cert.getPublicKey());
      cert.addExtension(subjectKeyID);
        
      cert.addExtension(certPolicies);                              
      cert.setValidNotAfter(date.getTime());
      // and sign the certificate
      cert.sign(algorithm ,privateKey);
    } catch (CertificateException ex) {
      throw new RuntimeException("Error creating the certificate: "+ex.getMessage());
    } catch (InvalidKeyException ex) {
      throw new RuntimeException("Error creating the certificate: "+ex.getMessage());
    } catch (NoSuchAlgorithmException ex) {
      throw new RuntimeException("Error creating the certificate: "+ex.getMessage());
    } catch (X509ExtensionException ex) {
      throw new RuntimeException("Error adding extension: "+ex.getMessage());   
    } catch (CodingException ex) {
      throw new RuntimeException("Error adding SubjectKeyIdentifier extension: "+ex.getMessage());   
    }     
    return cert;
  }

  /**
   * Loads or creates a KeyStore and initializes it.
   */
  private void initializeKeyStore() {

    BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
    String line;

    try {
      // default directory is the current user dir
      String keystore_dir = System.getProperty("user.dir");
      File ks = new File(keystore_dir, KS_FILENAME);

      // KeyStore does already exist
      if (ks.exists()) {
        keystore_file = ks.getAbsolutePath();
        if (create_only_certificates) {
          System.out.println("Create only new certificates from already existing keys!");
        }
        else {
          System.out.println("Existing KeyStore will be deleted!");
        }
        System.out.println("KeyStore: "+keystore_file);
      }
      else {
        // there is no KeyStore -> create also new keys
        create_only_certificates = false;
      
        while (true) {
          System.out.print("Create new KeyStore in directory: "+keystore_dir+" [y]");
          line = readLine(reader);
          if (line.length() == 0 || line.equals("y")) {
            ks = new File(keystore_dir, KS_FILENAME);
            keystore_file = ks.getAbsolutePath();
            System.out.println("KeyStore will be saved to: "+keystore_file);
            break;
          }
          System.out.print("Enter directory: ");
          keystore_dir = readLine(reader);
        }
      }
      
      // get a new KeyStore obnject
      key_store = KeyStore.getInstance("IAIKKeyStore");
      
      if (create_only_certificates) {
        // take private keys from existing KeyStore
        FileInputStream ksStream = null;
        try {
          ksStream = new FileInputStream(ks); 
          key_store.load(ksStream, KS_PASSWORD);
        } finally {
          if (ksStream != null) {
            try {
              ksStream.close();
            } catch (IOException e) {
              // ignore
            }
          }
        }
      }
      else {
        // create a new KeyStore
        key_store.load(null, null);
      }
      
    } catch (Exception ex) {
      System.out.println("Error creating new IAIK KeyStore!");
      throw new RuntimeException("Error creating new KeyStore: "+ex.getMessage());
    }
  }

  /**
   * Saves the KeyStore to disk.
   */
  private void saveKeyStore() {
    FileOutputStream os = null;
    try {
      // write the KeyStore to disk
      os = new FileOutputStream(keystore_file);
      key_store.store(os, KS_PASSWORD);
      
    } catch (Exception ex) {
      System.out.println("Error saving KeyStore!");
      ex.printStackTrace();
    } finally {
      if (os != null) {
        try {
          os.close();
        } catch (IOException e) {
          // ignore
        }
      }
    }
  }

  /**
   * Adds the private key and the certificate chain to the key store.
   *
   * @param keyPair the key pair with the private key to be added
   * @param chain the certificate chain to be added
   * @param alias the alias for the keystore entry
   *
   * @exception KeyStoreException if an error occurs when trying to add the key
   */
  public void addToKeyStore(KeyPair keyPair, X509Certificate[] chain, String alias) throws KeyStoreException {
    key_store.setKeyEntry(alias, keyPair.getPrivate(), KS_PASSWORD, chain);
  }
  
  /**
   * Returns a KeyPair form the KeyStore.
   * 
   * @param type the type (e.g. {@link CMSEccKeyStoreConstants#ECDSA_192 "ECDSA.192"} 
   *             of the requested key pair
   * 
   * @return the KeyPair of the given type
   *
   * @exception Exception if some error occurs
   */
  private KeyPair getKeyPair(String type) throws Exception {
    PrivateKey privKey = (PrivateKey)key_store.getKey(type, KS_PASSWORD);
    PublicKey pubKey = key_store.getCertificateChain(type)[0].getPublicKey();
    return new KeyPair(pubKey, privKey);
  }

  /**
   * Get all private keys from the KeyStore.
   */
  private void getPrivateKeys() {
    try {
      ca_ecdsa = getKeyPair(CA_ECDSA);
    } catch (Exception ex) {
      System.out.println("Unable to get ECDSA CA key from KeyStore.");
      ex.printStackTrace();
    }
     
    // ECDSA
    try {
      ecdsa192 = getKeyPair(ECDSA_192);
      ecdsa224 = getKeyPair(ECDSA_224);
      ecdsa256 = getKeyPair(ECDSA_256);
      ecdsa384 = getKeyPair(ECDSA_384);
      ecdsa521 = getKeyPair(ECDSA_521);
    } catch (Exception ex) {
      System.out.println("Unable to get ECDSA keys from KeyStore.");
      ex.printStackTrace();
      create_ecdsa = false;
    }
    // ECDH
    try {
      ecdh192 = getKeyPair(ECDH_192);
      ecdh192_ = getKeyPair(ECDH_192_);
      ecdh256 = getKeyPair(ECDH_256);
      ecdh256_ = getKeyPair(ECDH_256_);
      ecdh384 = getKeyPair(ECDH_384);
      ecdh384_ = getKeyPair(ECDH_384_);
      ecdh521 = getKeyPair(ECDH_521);
      ecdh521_ = getKeyPair(ECDH_521_);
    } catch (Exception ex) {
      System.out.println("Unable to get ECDH keys from KeyStore.");
      ex.printStackTrace();
      create_ecdh = false;
    }
  }

  /**
   * Generates new prviate keys.
   */
  private void generatePrivateKeys() {
    try {
      // CA certificate
      try {
        System.out.println("generate ECDSA KeyPair for CA certificate...");
        ca_ecdsa = generateKeyPair(CA_KEYLENGTH);
      } catch (NoSuchAlgorithmException ex) {
        System.out.println("No implementation for DSA! DSA CA keys not created!\n");
      }
      
      if (create_ecdsa) {
  	    try {
          System.out.println("generate ECDSA KeyPair for a test certificate [192 bits]...");
    	  ecdsa192 = generateKeyPair(192);
          System.out.println("generate ECDSA KeyPair for a test certificate [224 bits]...");
          ecdsa224 = generateKeyPair(224);
          System.out.println("generate ECDSA KeyPair for a test certificate [256 bits]...");
    	  ecdsa256 = generateKeyPair(256);
          System.out.println("generate ECDSA KeyPair for a test certificate [384 bits]...");
          ecdsa384 = generateKeyPair(384);
          System.out.println("generate ECDSA KeyPair for a test certificate [521 bits]...");
          ecdsa521 = generateKeyPair(521);
  	    } catch (NoSuchAlgorithmException ex) {
          create_ecdsa = false;
          System.out.println("No implementation for ECDSA! ECDSA keys are not created!\n");
  	    }
      }
      
      if (create_ecdh) {
        try {
          System.out.println("generate ECDH KeyPair for a test certificate [192 bits]...");
    	  ecdh192 = generateKeyPair(192);
          System.out.println("generate second ECDH KeyPair for a test certificate [192 bits]...");
          ecdh192_ = generateKeyPair(192);
          System.out.println("generate ECDH KeyPair for a test certificate [256 bits]...");
    	  ecdh256 = generateKeyPair(256);
          System.out.println("generate second ECDH KeyPair for a test certificate [256 bits]...");
          ecdh256_ = generateKeyPair(256);
          System.out.println("generate ECDH KeyPair for a test certificate [384 bits]...");
          ecdh384 = generateKeyPair(384);
          System.out.println("generate second ECDH KeyPair for a test certificate [384 bits]...");
          ecdh384_ = generateKeyPair(384);
          System.out.println("generate ECDH KeyPair for a test certificate [521 bits]...");
          ecdh521 = generateKeyPair(521);
          System.out.println("generate second ECDH KeyPair for a test certificate [521 bits]...");
          ecdh521_ = generateKeyPair(521);
  	    } catch (NoSuchAlgorithmException ex) {
          create_ecdh = false;
          System.out.println("No implementation for ECDH! ECDH keys are not created!\n");
  	    }
  	  }  
  	    	  
    } catch (Exception ex) {
      System.out.println("Exception: "+ex);
    }
  }
  
  /**
   * Generates the certificates.
   */
  public void generateCertificates() {

    try {

      // Now create the certificates
      Name issuer = new Name();
      issuer.addRDN(ObjectID.country, "AT");
      issuer.addRDN(ObjectID.organization ,"IAIK");
      issuer.addRDN(ObjectID.organizationalUnit ,"JavaSecurity");

      Name subject = new Name();
      subject.addRDN(ObjectID.country, "AT");
      subject.addRDN(ObjectID.organization ,"IAIK");
      subject.addRDN(ObjectID.organizationalUnit ,"JavaSecurity");

      //
      // create self signed CA certs
      //
      X509Certificate caECDSA = null;
      X509Certificate[] chain = new X509Certificate[1];
      // for verifying the created certificates
      SimpleChainVerifier verifier = new SimpleChainVerifier();
      // for interoperability we use ecdsaWithSHA1 as signature algorithm
      AlgorithmID signatureAlgorithm = (AlgorithmID)CMSAlgorithmID.ecdsa_With_SHA1.clone();

      issuer.addRDN(ObjectID.commonName ,"IAIK CMS-ECC Test ECDSA CA");
      System.out.println("create self signed ECDSA CA certificate...");
      caECDSA = createCertificate(issuer, ca_ecdsa.getPublic(),
         issuer, ca_ecdsa.getPrivate(), (AlgorithmID)signatureAlgorithm.clone(), null, true);
      // verify the self signed certificate
      caECDSA.verify();
      // set the CA cert as trusted root
      verifier.addTrustedCertificate(caECDSA);
      chain[0] = caECDSA;
      addToKeyStore(ca_ecdsa, chain, CA_ECDSA);
      
      //
      // create certificates
      //
      chain = new X509Certificate[2];
            
       
      // create a ECDSA test certificate
      if (create_ecdsa) {
        // 192
        subject.addRDN(ObjectID.commonName ,"ECDSA 192 bit Demo Certificate");
        System.out.println("create 192 bit ECDSA demo certificate...");
        SubjectKeyIdentifier subjectKeyID = (SubjectKeyIdentifier)caECDSA.getExtension(SubjectKeyIdentifier.oid);
        chain[0] = createCertificate(subject, ecdsa192.getPublic(),
              issuer, ca_ecdsa.getPrivate(), (AlgorithmID)signatureAlgorithm.clone(), subjectKeyID.get(), true);
        chain[1] = caECDSA;
        verifier.verifyChain(chain);
        
        addToKeyStore(ecdsa192, chain, ECDSA_192);
        subject.removeRDN(ObjectID.commonName);
        
        
        // 224
        subject.addRDN(ObjectID.commonName ,"ECDSA 224 bit Demo Certificate");
        System.out.println("create 224 bit ECDSA demo certificate...");
        subjectKeyID = (SubjectKeyIdentifier)caECDSA.getExtension(SubjectKeyIdentifier.oid);
        chain[0] = createCertificate(subject, ecdsa224.getPublic(),
              issuer, ca_ecdsa.getPrivate(), (AlgorithmID)signatureAlgorithm.clone(), subjectKeyID.get(), true);
        chain[1] = caECDSA;
        verifier.verifyChain(chain);
        
        addToKeyStore(ecdsa224, chain, ECDSA_224);
        subject.removeRDN(ObjectID.commonName);

        
        // 256
        subject.addRDN(ObjectID.commonName ,"ECDSA 256 bit Demo Certificate");
        System.out.println("create 256 bit ECDSA demo certificate...");
        chain[0] = createCertificate(subject, ecdsa256.getPublic(),
              issuer, ca_ecdsa.getPrivate(), (AlgorithmID)signatureAlgorithm.clone(), subjectKeyID.get(), true);
        chain[1] = caECDSA;
        verifier.verifyChain(chain);
        addToKeyStore(ecdsa256, chain, ECDSA_256);
        subject.removeRDN(ObjectID.commonName);
        
        
        // 384
        subject.addRDN(ObjectID.commonName ,"ECDSA 384 bit Demo Certificate");
        System.out.println("create 384 bit ECDSA demo certificate...");
        chain[0] = createCertificate(subject, ecdsa384.getPublic(),
              issuer, ca_ecdsa.getPrivate(), (AlgorithmID)signatureAlgorithm.clone(), subjectKeyID.get(), true);
        chain[1] = caECDSA;
        verifier.verifyChain(chain);
        addToKeyStore(ecdsa384, chain, ECDSA_384);
        subject.removeRDN(ObjectID.commonName);
        
        
        // 521
        subject.addRDN(ObjectID.commonName ,"ECDSA 521 bit Demo Certificate");
        System.out.println("create 521 bit ECDSA demo certificate...");
        subjectKeyID = (SubjectKeyIdentifier)caECDSA.getExtension(SubjectKeyIdentifier.oid);
        chain[0] = createCertificate(subject, ecdsa521.getPublic(),
              issuer, ca_ecdsa.getPrivate(), (AlgorithmID)signatureAlgorithm.clone(), subjectKeyID.get(), true);
        chain[1] = caECDSA;
        verifier.verifyChain(chain);
        
        addToKeyStore(ecdsa521, chain, ECDSA_521);
        subject.removeRDN(ObjectID.commonName);


      }
      
      // create a ECDH test certificate
      if (create_ecdh) {
        // 192
        subject.addRDN(ObjectID.commonName ,"ECDH 192 bit Demo Certificate 1");
        System.out.println("create 192 bit ECDH demo certificate...");
        SubjectKeyIdentifier subjectKeyID = (SubjectKeyIdentifier)caECDSA.getExtension(SubjectKeyIdentifier.oid);
        chain[0] = createCertificate(subject, ecdh192.getPublic(),
              issuer, ca_ecdsa.getPrivate(), (AlgorithmID)signatureAlgorithm.clone(), subjectKeyID.get(), false);
        chain[1] = caECDSA;
        verifier.verifyChain(chain);
        addToKeyStore(ecdh192, chain, ECDH_192);
        subject.removeRDN(ObjectID.commonName);
        
        // 192
        subject.addRDN(ObjectID.commonName ,"ECDH 192 bit Demo Certificate 2");
        System.out.println("create 192 bit ECDH demo certificate...");
        chain[0] = createCertificate(subject, ecdh192_.getPublic(),
              issuer, ca_ecdsa.getPrivate(), (AlgorithmID)signatureAlgorithm.clone(), subjectKeyID.get(), false);
        chain[1] = caECDSA;
        verifier.verifyChain(chain);
        addToKeyStore(ecdh192_, chain, ECDH_192_);
        subject.removeRDN(ObjectID.commonName);

        // 256
        subject.addRDN(ObjectID.commonName ,"ECDH 256 bit Demo Certificate 1");
        System.out.println("create 256 bit ECDH demo certificate...");
        chain[0] = createCertificate(subject, ecdh256.getPublic(),
              issuer, ca_ecdsa.getPrivate(), (AlgorithmID)signatureAlgorithm.clone(), subjectKeyID.get(), false);
        subject.removeRDN(ObjectID.commonName);
        chain[1] = caECDSA;
        verifier.verifyChain(chain);
        addToKeyStore(ecdh256, chain, ECDH_256);
        
        // 256
        subject.addRDN(ObjectID.commonName ,"ECDH 256 bit Demo Certificate 2");
        System.out.println("create 256 bit ECDH demo certificate...");
        chain[0] = createCertificate(subject, ecdh256_.getPublic(),
              issuer, ca_ecdsa.getPrivate(), (AlgorithmID)signatureAlgorithm.clone(), subjectKeyID.get(), false);
        subject.removeRDN(ObjectID.commonName);
        chain[1] = caECDSA;
        verifier.verifyChain(chain);
        addToKeyStore(ecdh256_, chain, ECDH_256_);
        
        
        // 384
        subject.addRDN(ObjectID.commonName ,"ECDH 384 bit Demo Certificate 1");
        System.out.println("create 384 bit ECDH demo certificate...");
        chain[0] = createCertificate(subject, ecdh384.getPublic(),
              issuer, ca_ecdsa.getPrivate(), (AlgorithmID)signatureAlgorithm.clone(), subjectKeyID.get(), false);
        subject.removeRDN(ObjectID.commonName);
        chain[1] = caECDSA;
        verifier.verifyChain(chain);
        addToKeyStore(ecdh384, chain, ECDH_384);
        
        
        // 384
        subject.addRDN(ObjectID.commonName ,"ECDH 384 bit Demo Certificate 2");
        System.out.println("create 384 bit ECDH demo certificate...");
        chain[0] = createCertificate(subject, ecdh384_.getPublic(),
              issuer, ca_ecdsa.getPrivate(), (AlgorithmID)signatureAlgorithm.clone(), subjectKeyID.get(), false);
        subject.removeRDN(ObjectID.commonName);
        chain[1] = caECDSA;
        verifier.verifyChain(chain);
        addToKeyStore(ecdh384_, chain, ECDH_384_);
        
        // 521
        subject.addRDN(ObjectID.commonName ,"ECDH 521 bit Demo Certificate 1");
        System.out.println("create 521 bit ECDH demo certificate...");
        chain[0] = createCertificate(subject, ecdh521.getPublic(),
              issuer, ca_ecdsa.getPrivate(), (AlgorithmID)signatureAlgorithm.clone(), subjectKeyID.get(), false);
        subject.removeRDN(ObjectID.commonName);
        chain[1] = caECDSA;
        verifier.verifyChain(chain);
        addToKeyStore(ecdh521, chain, ECDH_521);
        
        
        // 521
        subject.addRDN(ObjectID.commonName ,"ECDH 521 bit Demo Certificate 2");
        System.out.println("create 521 bit ECDH demo certificate...");
        chain[0] = createCertificate(subject, ecdh521_.getPublic(),
              issuer, ca_ecdsa.getPrivate(), (AlgorithmID)signatureAlgorithm.clone(), subjectKeyID.get(), false);
        subject.removeRDN(ObjectID.commonName);
        chain[1] = caECDSA;
        verifier.verifyChain(chain);
        addToKeyStore(ecdh521_, chain, ECDH_521_);
      }
      
      System.out.println("\nCertificates created!");
 
    } catch (Exception ex) {
      System.out.println("Exception: "+ex);
    }
  }
  
  /**
   * Reads the next line from the given BufferedReader.
   * 
   * @param reader the reader from which to read the line
   * 
   * @return the line just read
   * 
   * @throws IOException if an I/O error occurs
   */
  private final static String readLine(BufferedReader reader) throws IOException {
    String line = reader.readLine();
    if (line != null) {
      line = line.trim();
    } else {
      line = "";
    }
    return line;
  }
  
  /**
   * Starts the keystore setup.
   */
  public static void start() {
  	SetupCMSEccKeyStore suks = new SetupCMSEccKeyStore();
    suks.initializeKeyStore();
    if (suks.create_only_certificates) {
    	suks.getPrivateKeys();
    }
    else {
  	  suks.generatePrivateKeys();
  	}
  	suks.generateCertificates();
    suks.saveKeyStore();
  }
  
  /**
   * Creates the test certificates.
   */
  public static void main(String arg[]) throws IOException {

  	DemoUtil.initDemos();
  	try {
  	  ECCDemoUtil.installIaikEccProvider();
  	} catch (Exception e) {
  	  System.out.println(e.getMessage());
  	  e.printStackTrace();
  	  System.exit(1);
  	}
    start();    
    System.in.read();
  }
}