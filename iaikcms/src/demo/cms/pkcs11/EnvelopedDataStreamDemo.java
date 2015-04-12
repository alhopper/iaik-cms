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
// $Header: /IAIK-CMS/current/src/demo/cms/pkcs11/EnvelopedDataStreamDemo.java 14    23.08.13 14:27 Dbratko $
// $Revision: 14 $
//

package demo.cms.pkcs11;

// class and interface imports
import iaik.asn1.structures.AlgorithmID;
import iaik.cms.CMSException;
import iaik.cms.CertificateIdentifier;
import iaik.cms.EnvelopedDataStream;
import iaik.cms.KeyIdentifier;
import iaik.cms.KeyTransRecipientInfo;
import iaik.cms.RecipientInfo;
import iaik.x509.X509Certificate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Enumeration;

import demo.DemoUtil;



/**
 * This class shows how to en- and decrypt data with the CMS EnvelopedData 
 * type using the PKCS#11 provider for accessing the private key
 * on a smart card. This implementation uses the <code>SecurityProvider</code> 
 * feature of the CMS implementation of the IAIK-CMS toolkit.
 * <p>
 * For running this demo the following packages  are required (in addition to 
 * <code>iaik_cms.jar</code> and <code>iaik_cms_demo.jar</code>):
 * <ul>
 *    <li>
 *       <code>iaik_jce(full).jar</code> (IAIK-JCE crypto toolkit)
 *    </li>   
 *    <li>
 *       <code>iaikPkcs11Wrapper.jar</code> (IAIK PKCS#11 Wrapper)
 *    </li>
 *    <li>
 *       <code>iaikPkcs11Provider.jar</code> (IAIK PKCS#11 Provider)
 *    </li>
 *    <li>
 *       The shared PKCS#11 library (<code>pkcs11wrapper.dll</code> for Windows
 *       and <code>libpkcs11wrapper.so</code> for Unix)
 *    </li>  
 * </ul>
 * <code>iaik_cms.jar</code>, <code>iaik_cms_demo.jar</code>, <code>iaik_jce(full).jar</code>,
 * <code>iaikPkcs11Wrapper.jar</code> and <code>iaikPkcs11Provider.jar</code> have to
 * be put into the classpath, the shared library (<code>pkcs11wrapper.dll</code> or
 * <code>libpkcs11wrapper.so</code>) has to be in your system library search path
 * or in your VM library path, e.g. (on Windows, assuming that all jar files in a lib
 * sub-directory and the dll is in a lib/win32 sub-directory, and the module to be
 * used is \"aetpkss1.dll\" (for G&D StarCos and Rainbow iKey 3000)):
 * <pre>
 * java -Djava.library.path=lib/win32 
 *      -cp lib/iaik_jce.jar;lib/iaikPkcs11Wrapper.jar;lib/iaikPkcs11Provider.jar;lib/iaik_cms.jar;lib/iaik_cms_demo.jar
 *      demo.pkcs11.EnvelopedDataStreamDemo aetpkss1.dll 
 * </pre>
 * You must use JDK 1.2 or later for running this demo.
 * 
 * @author Dieter Bratko 
 */
public class EnvelopedDataStreamDemo extends PKCS11Demo {

  /**
   * The private key of the recipient. In this case only a proxy object, but the
   * application cannot see this. Used for decryption.
   */
  protected PrivateKey privateKey_;

  /**
   * The certificate of the recipient. In contrast to the private key, the
   * certificate holds holds the actual (public) keying material.
   * Used for encryption.
   */
  protected X509Certificate certificate_;

  /**
   * Creates a EnvelopedDataStreamDemo object for the given module name.
   * 
   * @param moduleName the name of the module
   * @param userPin the user-pin (password) for the TokenKeyStore
   *                (may be <code>null</code> to pou-up a dialog asking for the pin)
   * 
   */
  public EnvelopedDataStreamDemo(String moduleName, char[] userPin) {
    // install provider in super class
    super(moduleName, userPin);
    System.out.println();
    System.out.println("************************************************************************************************");
    System.out.println("*                            PKCS#11  EnvelopedDataStreamDemo                                  *");
    System.out.println("* (shows the usage of the CMS EnvelopedData type implementation with the IAIK-PKCS11 provider) *");
    System.out.println("************************************************************************************************");
    System.out.println();
  }
  

  /**
   * This method gets the key store of the PKCS#11 provider and searches for a
   * certificate and corresponding private key entry that can en/decrypt the data.
   * Key and cert are stored in the <code>privateKey_</code> and <code>certificate_</code>
   * member variables. Usually you only will have the smartcard on the decryption
   * side (i.e. the sender will get the certificate by other means to use it
   * for encrypting the message), however, for simplicity (and since we do not know
   * which certificate/card you are actually will use for running the demo) we
   * get both, key and certificate from the card.
   *
   * @exception GeneralSecurityException If anything with the provider fails.
   * @exception IOException If loading the key store fails.
   */
  public void getKeyAndCertificate()
      throws GeneralSecurityException, IOException, CMSException
  {
    
    // we simply take the first keystore, if there are serveral
    Enumeration aliases = tokenKeyStore_.aliases();

    // and we take the first private key for simplicity
    while (aliases.hasMoreElements()) {
      String keyAlias = aliases.nextElement().toString();
      Key key = null;
      try {
        key = tokenKeyStore_.getKey(keyAlias, null);
      } catch (NoSuchAlgorithmException ex) {
        throw new GeneralSecurityException(ex.toString());
      }
      if (key instanceof RSAPrivateKey) {
        Certificate[] certificateChain = tokenKeyStore_.getCertificateChain(keyAlias);
        if ((certificateChain != null) && (certificateChain.length > 0)) {
          java.security.cert.X509Certificate userCertificate = (java.security.cert.X509Certificate)certificateChain[0];
          boolean[] keyUsage = userCertificate.getKeyUsage();
          if ((keyUsage == null) || keyUsage[2] || keyUsage[3]) { // check for encryption, but also accept if none set
            // check if there is a receipient info for this certificate
            certificate_ = (userCertificate instanceof iaik.x509.X509Certificate) 
                           ? (iaik.x509.X509Certificate) userCertificate
                           : new iaik.x509.X509Certificate(userCertificate.getEncoded());
                System.out.println("##########");
                privateKey_ = (PrivateKey) key;
                System.out.println("The decrpytion key is: " + privateKey_);
                System.out.println("##########");
                System.out.println("##########");
                System.out.println("The encryption certificate is:");
                System.out.println(certificate_.toString());
                System.out.println("##########");
          }
        }  
      }
    }

    if (privateKey_ == null) {
      System.out.println("Found no decryption key. Ensure that the correct card is inserted and contains a key that is suitable for decryption.");
      System.exit(0);
    }
  }
  
  /**
   * This method uses the CMS EnvelopedData type to encrypt the given data. It uses the 
   * certificate in the member variable set by <code>getKeyAndCertificate()</code>.
   *
   * @exception GeneralSecurityException
   *     If anything with the provider fails.
   * @exception IOFoundException
   *     If an I/O error occurs.
   * @exception CMSException If handling the CMS data fails.
   */
  public byte[] encrypt(byte[] data)
      throws GeneralSecurityException, IOException, CMSException
  {    
    System.out.println("##########");
    System.out.print("Encrypting data... ");
    
    ByteArrayInputStream dataInputStream = new ByteArrayInputStream(data);
    EnvelopedDataStream envelopedData = null;
    try {
      envelopedData = new EnvelopedDataStream(dataInputStream,
                                              (AlgorithmID)AlgorithmID.aes128_CBC.clone());
    } catch (NoSuchAlgorithmException ex) {
      throw new GeneralSecurityException(ex.toString());
    }

    // create RecipientInfo
    X509Certificate recipientCertificate = certificate_;
    RecipientInfo recipient = 
        new KeyTransRecipientInfo(recipientCertificate, 
                                  CertificateIdentifier.ISSUER_AND_SERIALNUMBER, 
                                  (AlgorithmID)AlgorithmID.rsaEncryption.clone());

    envelopedData.setRecipientInfos(new RecipientInfo[] { recipient } );

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    envelopedData.writeTo(baos);

    return baos.toByteArray();
  }


  /**
   * This method decrypts the data from the provided CMS EnvelopedData.
   * It uses the key and certificate in the member variables set by  
   * <code>getKeyAndCertificate()</code>.
   *
   * @exception GeneralSecurityException
   *     If anything with the provider fails.
   * @exception IOException
   *     If an I/O error occurs.
   * @exception CMSException If handling the CMS data fails.
   */
  public byte[] decrypt(byte[] encodedEnvelopedData)
      throws GeneralSecurityException, IOException, CMSException
  {    
    System.out.println("##########");
    System.out.print("Decrypting data... ");
    
    InputStream inputStream = new ByteArrayInputStream(encodedEnvelopedData);
    EnvelopedDataStream envelopedData = new EnvelopedDataStream(inputStream);
    
    RecipientInfo[] recipientInfos = envelopedData.getRecipientInfos();
    System.out.println("Included RecipientInfos: ");
    for (int recipientIndex = 0; recipientIndex < recipientInfos.length; recipientIndex++) {
      System.out.print("Recipient Info " + (recipientIndex+1) + ": ");
      KeyIdentifier[] keyIdentifiers = recipientInfos[recipientIndex].getRecipientIdentifiers();
      for (int keyIdentifierIndex = 0; keyIdentifierIndex < keyIdentifiers.length; keyIdentifierIndex++) {
        System.out.print(keyIdentifiers[keyIdentifierIndex]);
      }
      System.out.println();
    }
    
    // setup cipher engine for decryption
    try {
      envelopedData.setupCipher(privateKey_, certificate_);
    } catch (InvalidKeyException ex) {
      throw new GeneralSecurityException(ex.toString());
    } catch (NoSuchAlgorithmException ex) {
      throw new GeneralSecurityException(ex.toString());
    }

    // read and decrypt data
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    InputStream dataInput = envelopedData.getInputStream();
    byte[] buffer = new byte[2048];
    int bytesRead;
    while ((bytesRead = dataInput.read(buffer)) >= 0) {
      // write to output
      baos.write(buffer, 0, bytesRead);
    }
     
    System.out.println("##########");
    return baos.toByteArray();
  }

  /**
   * Starts the demo.
   */
  public void start() {
    try {
      byte[] testMessage = "This is the test message to be encrypted!".getBytes("ASCII");
      getKeyStore();
      getKeyAndCertificate();
      // encrypt
      byte[] envelopedData = encrypt(testMessage);
      // decrypt
      byte[] content = decrypt(envelopedData);
      System.out.println("##########");
      // we know that we had a text content, thus we can convert into a String
      System.out.println("Content: " + new String(content, "ASCII"));
      System.out.println("##########");
    } catch (Throwable ex) {
      ex.printStackTrace();
      throw new RuntimeException(ex.toString());
    }
  }
  
  /**
   * This is the main method that is called by the JVM during startup.
   *
   * @param args These are the command line arguments.
   */
  public static void main(String[] args) {

    if (args.length == 0) {
      System.out.println("Missing pkcs11 module name.\n");
      printUsage();
    }
    
    String moduleName = args[0];
    char[] userPin = (args.length == 2) ? args[1].toCharArray() : null;
    
    if (args.length > 2) {
      System.out.println("Too many arguments.\n");
      printUsage();
    }
    
    DemoUtil.initDemos();
    
    (new EnvelopedDataStreamDemo(moduleName, userPin)).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
  
  /**
   * Print usage information.
   */
  private final static void printUsage() {
    System.out.println("Usage:\n");
    System.out.println("java EnvelopedDataStreamDemo <pkcs11 module name> [<user-pin>]\n");
    System.out.println("e.g.:");
    System.out.println("java EnvelopedDataStreamDemo aetpkss1.dll");
    System.out.println("java EnvelopedDataStreamDemo aetpkss1.so");
    DemoUtil.waitKey();
    System.exit(0);
  }




}