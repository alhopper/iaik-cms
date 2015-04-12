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
// $Header: /IAIK-CMS/current/src/demo/cms/ecc/keystore/CMSEccKeyStore.java 18    11.07.12 11:03 Dbratko $
// $Revision: 18 $
//

package demo.cms.ecc.keystore;

import iaik.utils.Util;
import iaik.x509.X509Certificate;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;

/**
 * Keystore for the ECC demos of IAIK-CMS.
 * 
 * @author Dieter Bratko
 */
public class CMSEccKeyStore implements CMSEccKeyStoreConstants {

  /**
   * Certificates.
   */
  static Object[][] certificates = new Object[2][13];
  /**
   * Keys.
   */
  static PrivateKey[][] keys = new PrivateKey[2][13];
  /**
   * Ca certificate.
   */
  static X509Certificate ca_certificate;
  /**
   * Ca key.
   */
  static PrivateKey ca_key;

  public final static int ECDSA = 0;
  public final static int ECDH = 1;
  
  public final static int SZ_192_SIGN = 0;
  public final static int SZ_224_SIGN = 1;
  public final static int SZ_256_SIGN = 2;
  public final static int SZ_384_SIGN = 3;
  public final static int SZ_521_SIGN = 4;
  public final static int SZ_192_CRYPT = 5;
  public final static int SZ_192_CRYPT_ = 6;
  public final static int SZ_256_CRYPT = 7;
  public final static int SZ_256_CRYPT_ = 8;
  public final static int SZ_384_CRYPT = 9;
  public final static int SZ_384_CRYPT_ = 10;
  public final static int SZ_521_CRYPT = 11;
  public final static int SZ_521_CRYPT_ = 12;
  
  /**
   * Keystore.
   */
  static KeyStore key_store;
  
  /**
   * Loads and inits keystore.
   */
  static {
    System.out.println("initializing KeyStore...");
    loadKeyStore();
    initKeyStore();
  }
  
  /**
   * Loads the keystore from the file ("cmsecc.keystore").
   */
  private static void loadKeyStore() {
    boolean createKeyStore = false;
    // try to locate the KeyStore
    // first check the current working directory
    File ks = new File(KS_DIRECTORY, KS_FILENAME);
    if (!ks.exists()) {
      createKeyStore = true;
      // called from demo batch file (try parent directory)
      File ksDir = new File(KS_DIRECTORY);
      if (ksDir.exists()) {
        String parentDir = ksDir.getParent();
        String pDir = parentDir.toLowerCase(); 
        if ((pDir.endsWith("cms")) || (pDir.endsWith("smime"))) {
          File ksParent = new File(parentDir, KS_FILENAME);
          if (ksParent.exists()) {
            ks = ksParent;
            createKeyStore = false;
          }
        }
      }
      if (createKeyStore) {
        // keystore does not exist ==> create new one
        System.out.println();
        System.out.println();
        System.out.println("Can not find the KeyStore " + KS_FILENAME + " in directory:");
        System.out.println(ks.getAbsolutePath());
        System.out.println("Generating key store!");
        try {
          SetupCMSEccKeyStore.main(new String[] {});
        } catch (Exception ex) {
          System.out.println("Unable to create KeyStore!");
          ex.printStackTrace();
          demo.DemoUtil.waitKey();
          System.exit(1);
        }   
      }  
    }

    FileInputStream fis = null;
    // now try to create and load the KeyStore
    try {
      fis = new FileInputStream(ks);
      key_store = KeyStore.getInstance("IAIKKeyStore", "IAIK");
      key_store.load(fis, KS_PASSWORD);
      fis.close();
    } catch (Exception ex) {
      System.out.println("Unable to load KeyStore!");
      ex.printStackTrace();
      if (fis != null) {
        try {
          fis.close(); 
        } catch (Exception e) {
          // ignore
        }
      }
      demo.DemoUtil.waitKey();
      System.exit(1);
    } 
  }

  /**
   * Initializes the keystore.
   */
  private static void initKeyStore() {
    try {
      ca_certificate = Util.convertCertificateChain(key_store.getCertificateChain(CA_ECDSA))[0];
      ca_key = (PrivateKey)key_store.getKey(CA_ECDSA, KS_PASSWORD);

      certificates[ECDSA][SZ_192_SIGN] = Util.convertCertificateChain(key_store.getCertificateChain(ECDSA_192));
      keys[ECDSA][SZ_192_SIGN] = (PrivateKey)key_store.getKey(ECDSA_192, KS_PASSWORD);
      certificates[ECDSA][SZ_224_SIGN] = Util.convertCertificateChain(key_store.getCertificateChain(ECDSA_224));
      keys[ECDSA][SZ_224_SIGN] = (PrivateKey)key_store.getKey(ECDSA_224, KS_PASSWORD);
      certificates[ECDSA][SZ_256_SIGN] = Util.convertCertificateChain(key_store.getCertificateChain(ECDSA_256));
      keys[ECDSA][SZ_256_SIGN] = (PrivateKey)key_store.getKey(ECDSA_256, KS_PASSWORD);
      certificates[ECDSA][SZ_384_SIGN] = Util.convertCertificateChain(key_store.getCertificateChain(ECDSA_384));
      keys[ECDSA][SZ_384_SIGN] = (PrivateKey)key_store.getKey(ECDSA_384, KS_PASSWORD);
      certificates[ECDSA][SZ_521_SIGN] = Util.convertCertificateChain(key_store.getCertificateChain(ECDSA_521));
      keys[ECDSA][SZ_521_SIGN] = (PrivateKey)key_store.getKey(ECDSA_521, KS_PASSWORD);
      
    } catch (Exception ex) {
      System.out.println("Unable to get ECDSA certificates from KeyStore.");
      ex.printStackTrace();
    }

    try {
      certificates[ECDH][SZ_192_CRYPT] = Util.convertCertificateChain(key_store.getCertificateChain(ECDH_192));
      keys[ECDH][SZ_192_CRYPT] = (PrivateKey)key_store.getKey(ECDH_192, KS_PASSWORD);
      certificates[ECDH][SZ_192_CRYPT_] = Util.convertCertificateChain(key_store.getCertificateChain(ECDH_192_));
      keys[ECDH][SZ_192_CRYPT_] = (PrivateKey)key_store.getKey(ECDH_192_, KS_PASSWORD);
      certificates[ECDH][SZ_256_CRYPT] = Util.convertCertificateChain(key_store.getCertificateChain(ECDH_256));
      keys[ECDH][SZ_256_CRYPT] = (PrivateKey)key_store.getKey(ECDH_256, KS_PASSWORD);
      certificates[ECDH][SZ_256_CRYPT_] = Util.convertCertificateChain(key_store.getCertificateChain(ECDH_256_));
      keys[ECDH][SZ_256_CRYPT_] = (PrivateKey)key_store.getKey(ECDH_256_, KS_PASSWORD);
      certificates[ECDH][SZ_384_CRYPT] = Util.convertCertificateChain(key_store.getCertificateChain(ECDH_384));
      keys[ECDH][SZ_384_CRYPT] = (PrivateKey)key_store.getKey(ECDH_384, KS_PASSWORD);
      certificates[ECDH][SZ_384_CRYPT_] = Util.convertCertificateChain(key_store.getCertificateChain(ECDH_384_));
      keys[ECDH][SZ_384_CRYPT_] = (PrivateKey)key_store.getKey(ECDH_384_, KS_PASSWORD);
      
      certificates[ECDH][SZ_521_CRYPT] = Util.convertCertificateChain(key_store.getCertificateChain(ECDH_521));
      keys[ECDH][SZ_521_CRYPT] = (PrivateKey)key_store.getKey(ECDH_521, KS_PASSWORD);
      certificates[ECDH][SZ_521_CRYPT_] = Util.convertCertificateChain(key_store.getCertificateChain(ECDH_521_));
      keys[ECDH][SZ_521_CRYPT_] = (PrivateKey)key_store.getKey(ECDH_521_, KS_PASSWORD);
    } catch (Exception ex) {
      System.out.println("Unable to get ECDH certificate from KeyStore.");
      ex.printStackTrace();
    }
  }
  
  /**
   * Returns the private key of a CA certificate.
   *
   * @param type {@link #ECDSA ECDSA} or {@link #ECDH ECDH}
   * @param size the key size
   * 
   * @return the key
   */
  public static PrivateKey getPrivateKey(int type, int size) {
    try {
      return keys[type][size];
    } catch (ArrayIndexOutOfBoundsException ex) {
      throw new RuntimeException("Wrong type or size!");
    }
  }

  /**
   * Returns a demo user certificate.
   *
   * @param type {@link #ECDSA ECDSA} or {@link #ECDH ECDH} 
   * @param size the size of the corresponding key
   * 
   * @return the certificate chain
   */
  public static X509Certificate[] getCertificateChain(int type, int size) {
    try {
      return (X509Certificate[])certificates[type][size];
    } catch (ArrayIndexOutOfBoundsException ex) {
      throw new RuntimeException("Wrong type or size!");
    }
  }
  
  /**
   * Returns the private key of a CA certificate.
   *
   * @return the private key of the ca
   */
  public static PrivateKey getCaPrivateKey() {
    return ca_key;
  }

  /**
   * Returns the demo CA certificate.
   *
   * @return the demo CA certificate
   */
  public static X509Certificate getCaCertificate() {
    return ca_certificate;
  }
}
