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
// $Header: /IAIK-CMS/current/src/demo/keystore/CMSKeyStore.java 21    11.07.12 11:03 Dbratko $
// $Revision: 21 $
//

package demo.keystore;

import iaik.utils.Util;
import iaik.x509.X509Certificate;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;

/**
 * KeyStore repository used providing keys and certificates
 * for the several CMS and S/MIME demos.
 * <p>
 * Reads and loads keys and certificates from an IaikKeyStore
 * files and provides methods to access the keys and certificates
 * based on algorithm name and algorithm type.
 * 
 * @author Dieter Bratko
 */
public class CMSKeyStore implements CMSKeyStoreConstants {
  
  /**
   * Certificates.
   */
  static Object[][] certificates = new Object[4][8];
  /**
   * Keys.
   */
  static PrivateKey[][] keys = new PrivateKey[4][8];
  /**
   * Ca certificates.
   */
  static X509Certificate[] ca_certificates = new X509Certificate[2];
  /**
   * Ca keys.
   */
  static PrivateKey[] ca_keys = new PrivateKey[2];
  
  /**
   * Indices into the cert/key tables
   */
  public final static int RSA = 0;
  public final static int DSA = 1;
  public final static int ESDH = 2;
  public final static int SSDH = 3;

  public final static int SZ_512_SIGN = 0;
  public final static int SZ_1024_SIGN = 1;
  public final static int SZ_2048_SIGN = 2;
  public final static int SZ_3072_SIGN = 3;
  public final static int SZ_512_CRYPT = 4;
  public final static int SZ_1024_CRYPT = 5;
  public final static int SZ_1024_CRYPT_ = 6;
  public final static int SZ_2048_CRYPT = 7;
  
  /**
   * Certificate chain of demo time stamp server.
   */
  static X509Certificate[] tsp_server_certs;
  
  /**
   * Key of demo time stamp server.
   */
  static PrivateKey tsp_server_key;

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
    System.out.println();
  }
  
  /**
   * Loads the keystore from the file ("cms.keystore").
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
          SetupCMSKeyStore.main(new String[] {});
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
      ca_certificates[RSA] = Util.convertCertificateChain(key_store.getCertificateChain(CA_RSA))[0];
      ca_keys[RSA] = (PrivateKey)key_store.getKey(CA_RSA, KS_PASSWORD);
      
      // RSA for signing
      certificates[RSA][SZ_512_SIGN] = Util.convertCertificateChain(key_store.getCertificateChain(RSA_512_SIGN));
      keys[RSA][SZ_512_SIGN] = (PrivateKey)key_store.getKey(RSA_512_SIGN, KS_PASSWORD);
      certificates[RSA][SZ_1024_SIGN] = Util.convertCertificateChain(key_store.getCertificateChain(RSA_1024_SIGN));
      keys[RSA][SZ_1024_SIGN] = (PrivateKey)key_store.getKey(RSA_1024_SIGN, KS_PASSWORD);
      certificates[RSA][SZ_2048_SIGN] = Util.convertCertificateChain(key_store.getCertificateChain(RSA_2048_SIGN));
      keys[RSA][SZ_2048_SIGN] = (PrivateKey)key_store.getKey(RSA_2048_SIGN, KS_PASSWORD);
      // RSA for encrypting
      certificates[RSA][SZ_512_CRYPT] = Util.convertCertificateChain(key_store.getCertificateChain(RSA_512_CRYPT));
      keys[RSA][SZ_512_CRYPT] = (PrivateKey)key_store.getKey(RSA_512_CRYPT, KS_PASSWORD);
      certificates[RSA][SZ_1024_CRYPT] = Util.convertCertificateChain(key_store.getCertificateChain(RSA_1024_CRYPT));
      keys[RSA][SZ_1024_CRYPT] = (PrivateKey)key_store.getKey(RSA_1024_CRYPT, KS_PASSWORD);
      certificates[RSA][SZ_1024_CRYPT_] = Util.convertCertificateChain(key_store.getCertificateChain(RSA_1024_CRYPT_));
      keys[RSA][SZ_1024_CRYPT_] = (PrivateKey)key_store.getKey(RSA_1024_CRYPT_, KS_PASSWORD);
      certificates[RSA][SZ_2048_CRYPT] = Util.convertCertificateChain(key_store.getCertificateChain(RSA_2048_CRYPT));
      keys[RSA][SZ_2048_CRYPT] = (PrivateKey)key_store.getKey(RSA_2048_CRYPT, KS_PASSWORD);
      
    } catch (Exception ex) {
      System.out.println("RSA certificates not loaded: " + ex.getMessage());
      // ex.printStackTrace();
    }

    try {
      ca_certificates[DSA] = Util.convertCertificateChain(key_store.getCertificateChain(CA_DSA))[0];
      ca_keys[DSA] = (PrivateKey)key_store.getKey(CA_DSA, KS_PASSWORD);

      certificates[DSA][SZ_512_SIGN] = Util.convertCertificateChain(key_store.getCertificateChain(DSA_512));
      keys[DSA][SZ_512_SIGN] = (PrivateKey)key_store.getKey(DSA_512, KS_PASSWORD);
      certificates[DSA][SZ_1024_SIGN] = Util.convertCertificateChain(key_store.getCertificateChain(DSA_1024));
      keys[DSA][SZ_1024_SIGN] = (PrivateKey)key_store.getKey(DSA_1024, KS_PASSWORD);
      
    } catch (Exception ex) {
      System.out.println("DSA certificates not loaded: " + ex.getMessage());
      // ex.printStackTrace();
    }
    
    try {
      certificates[DSA][SZ_2048_SIGN] = Util.convertCertificateChain(key_store.getCertificateChain(DSA_2048));
      keys[DSA][SZ_2048_SIGN] = (PrivateKey)key_store.getKey(DSA_2048, KS_PASSWORD);
      certificates[DSA][SZ_3072_SIGN] = Util.convertCertificateChain(key_store.getCertificateChain(DSA_3072));
      keys[DSA][SZ_3072_SIGN] = (PrivateKey)key_store.getKey(DSA_3072, KS_PASSWORD);
    } catch (Exception ex) {
      System.out.println("Unable to get DSA SHA-2 certificate from KeyStore: " + ex.getMessage());
    }

    try {
      certificates[ESDH][SZ_512_CRYPT] = Util.convertCertificateChain(key_store.getCertificateChain(ESDH_512));
      keys[ESDH][SZ_512_CRYPT] = (PrivateKey)key_store.getKey(ESDH_512, KS_PASSWORD);
      certificates[ESDH][SZ_1024_CRYPT] = Util.convertCertificateChain(key_store.getCertificateChain(ESDH_1024));
      keys[ESDH][SZ_1024_CRYPT] = (PrivateKey)key_store.getKey(ESDH_1024, KS_PASSWORD);
      certificates[ESDH][SZ_1024_CRYPT_] = Util.convertCertificateChain(key_store.getCertificateChain(ESDH_1024_));
      keys[ESDH][SZ_1024_CRYPT_] = (PrivateKey)key_store.getKey(ESDH_1024_, KS_PASSWORD);
      certificates[ESDH][SZ_2048_CRYPT] = Util.convertCertificateChain(key_store.getCertificateChain(ESDH_2048));
      keys[ESDH][SZ_2048_CRYPT] = (PrivateKey)key_store.getKey(ESDH_2048, KS_PASSWORD);
      certificates[SSDH][SZ_1024_CRYPT] = Util.convertCertificateChain(key_store.getCertificateChain(SSDH_1024));
      keys[SSDH][SZ_1024_CRYPT] = (PrivateKey)key_store.getKey(SSDH_1024, KS_PASSWORD);
      certificates[SSDH][SZ_1024_CRYPT_] = Util.convertCertificateChain(key_store.getCertificateChain(SSDH_1024_));
      keys[SSDH][SZ_1024_CRYPT_] = (PrivateKey)key_store.getKey(SSDH_1024_, KS_PASSWORD);
    } catch (Exception ex) {
      System.out.println("Diffie-Hellman certificates not loaded: " + ex.getMessage());
      // ex.printStackTrace();
    }

    //  TSP server cert
    try {
      tsp_server_certs = Util.convertCertificateChain(key_store.getCertificateChain(TSP_SERVER));
      tsp_server_key = (PrivateKey)key_store.getKey(TSP_SERVER, KS_PASSWORD);
    } catch (Exception ex) {
      System.out.println("TSP server certificate not loaded: " + ex.getMessage());
      // ex.printStackTrace();
    }
  }
  
  /**
   * Returns the private key of a CA certificate.
   *
   * @param type {@link #RSA RSA} or {@link #DSA DSA} or {@link #ESDH ESDH}
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
   * @param type {@link #RSA RSA} or {@link #DSA DSA} or {@link #ESDH ESDH} or {@link #SSDH SSDH}
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
   * @param type {@link #RSA RSA} or {@link #DSA DSA}
   * 
   * @return the key
   */
  public static PrivateKey getCaPrivateKey(int type) {
    try {
      return ca_keys[type];
    } catch (ArrayIndexOutOfBoundsException ex) {
      throw new RuntimeException("Wrong type or size!");
    }
  }

  /**
   * Returns a demo CA certificate.
   *
   * @param type {@link #RSA RSA} or {@link #DSA DSA}
   * 
   * @return the ca certificate
   */
  public static X509Certificate getCaCertificate(int type) {
    try {
      return ca_certificates[type];
    } catch (ArrayIndexOutOfBoundsException ex) {
      throw new RuntimeException("Wrong type or size!");
    }
  }
  
  /**
   * Returns the private key of the TSP demo server.
   * 
   * @return the key
   */
  public static PrivateKey getTspServerPrivateKey() {
    return tsp_server_key;
  }

  /**
   * Returns the certificate chain of the TSP demo server.
   * 
   * @return the tsp server certificate
   */
  public static X509Certificate[] getTspServerCertificate() {
    return tsp_server_certs;
  }

}
