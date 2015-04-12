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
// $Header: /IAIK-CMS/current/src/demo/cms/pkcs7cms/PKCS7CMSEncryptedDataDemo.java 14    23.08.13 14:27 Dbratko $
// $Revision: 14 $
//

package demo.cms.pkcs7cms;

import iaik.asn1.ASN1Object;
import iaik.asn1.structures.AlgorithmID;
import iaik.cms.CMSException;
import iaik.cms.EncryptedContentInfo;
import iaik.cms.EncryptedContentInfoStream;
import iaik.cms.EncryptedData;
import iaik.cms.EncryptedDataStream;
import iaik.security.random.SecRandom;
import iaik.utils.Util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;

import demo.DemoUtil;

/**
 * Tests the IAIK CMS against the IAIK PKCS#7 EncryptedData(Stream) implementation.
 * 
 * @author Dieter Bratko
 */
public class PKCS7CMSEncryptedDataDemo {

  // secure random number generator
  SecureRandom random;

  /**
   * Default constructor.
   */
  public PKCS7CMSEncryptedDataDemo() {
    
    System.out.println();
    System.out.println("***********************************************************************************************");
    System.out.println("*                                 PKCS7CMSEncryptedDataDemo                                   *");
    System.out.println("* (tests the CMS EncryptedData against the IAIK-JCE PKCS#7 EncryptedData type implementation) *");
    System.out.println("***********************************************************************************************");
    System.out.println();
    
    random = SecRandom.getDefault();
  }


  /**
   * Creates a CMS <code>EncryptedDataStream</code> message.
   * <p>
   * The supplied content is PBE-encrypted using the specified password.
   *
   * @param message the message to be encrypted, as byte representation
   * @param pbeAlgorithm the PBE algorithm to be used
   * @param password the password
   * @return the DER encoding of the <code>EncryptedData</code> object just created
   * @exception CMSException if the <code>EncryptedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createEncryptedDataStream(byte[] message, AlgorithmID pbeAlgorithm, char[] password) throws CMSException, IOException {

    EncryptedDataStream encrypted_data;

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);
    // create a new EnvelopedData object encrypted with TripleDES CBC
    try {
      encrypted_data = new EncryptedDataStream(is, 2048);
      encrypted_data.setupCipher(pbeAlgorithm, password);
    } catch (InvalidKeyException ex) {
      throw new CMSException("Key error: "+ex.toString());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.getMessage());
    }

    // return the EnvelopedDate as DER encoded byte array with block size 2048
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    encrypted_data.writeTo(os);
    return os.toByteArray();
  }

  /**
   * Decrypts the PBE-encrypted content of the given CMS <code>EncryptedData</code> object
   * using the specified password and returns the decrypted (= original) message.
   *
   * @param encoding the <code>EncryptedData</code> object as DER encoded byte array
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
    EncryptedDataStream encrypted_data = new EncryptedDataStream(is);

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
      throw new CMSException("Invalid Parameters: "+ex.toString());
    } catch (InvalidParameterSpecException ex) {
      throw new CMSException("Invalid Parameters: "+ex.toString());
    }
  }

  /**
   * Creates a CMS <code>EncryptedData</code> message.
   * <p>
   * The supplied content is PBE-encrypted using the specified password.
   *
   * @param message the message to be encrypted, as byte representation
   * @param pbeAlgorithm the PBE algorithm to be used
   * @param password the password
   * @return the DER encoding of the <code>EncryptedData</code> object just created
   * @exception CMSException if the <code>EncryptedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public ASN1Object createEncryptedData(byte[] message, AlgorithmID pbeAlgorithm, char[] password) throws CMSException, IOException {

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
    return encrypted_data.toASN1Object();

  }

  /**
   * Decrypts the PBE-encrypted content of the given CMS <code>EncryptedData</code> object
   * using the specified password and returns the decrypted (= original) message.
   *
   * @param asn1Object the <code>EncryptedData</code> object as ASN1Object
   * @param password the password to decrypt the message
   *
   * @return the recovered message, as byte array
   * @exception CMSException if the message cannot be recovered
   * @exception IOException if an I/O error occurs
   */
  public byte[] getEncryptedData(ASN1Object asn1Object, char[] password) throws CMSException, IOException {

    // create an EncryptedData from the ASN1Object
    EncryptedData encrypted_data = new EncryptedData(asn1Object);

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
  
  // PKCS#7
  
  
  /**
   * Creates a PKCS#7 <code>EncryptedDataStream</code> message.
   * <p>
   * The supplied content is PBE-encrypted using the specified password.
   *
   * @param message the message to be encrypted, as byte representation
   * @param pbeAlgorithm the PBE algorithm to be used
   * @param password the password
   * @return the DER encoding of the <code>EncryptedData</code> object just created
   * @exception iaik.pkcs.PKCSException if the <code>EncryptedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createPKCS7EncryptedDataStream(byte[] message, AlgorithmID pbeAlgorithm, char[] password) 
    throws iaik.pkcs.PKCSException, IOException {

    iaik.pkcs.pkcs7.EncryptedDataStream encrypted_data;

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);
    // create a new EnvelopedData object encrypted with TripleDES CBC
    try {
      encrypted_data = new iaik.pkcs.pkcs7.EncryptedDataStream(is, 2048);
      encrypted_data.setupCipher(pbeAlgorithm, password);
    } catch (InvalidKeyException ex) {
      throw new iaik.pkcs.PKCSException("Key error: "+ex.toString());
    } catch (NoSuchAlgorithmException ex) {
      throw new iaik.pkcs.PKCSException("Content encryption algorithm not implemented: "+ex.getMessage());
    }

    // return the EnvelopedDate as DER encoded byte array with block size 2048
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    encrypted_data.writeTo(os);
    return os.toByteArray();
  }

  /**
   * Decrypts the PBE-encrypted content of the given PKCS#7 <code>EncryptedData</code> object
   * using the specified password and returns the decrypted (= original) message.
   *
   * @param encoding the <code>EncryptedData</code> object as DER encoded byte array
   * @param password the password to decrypt the message
   *
   * @return the recovered message, as byte array
   * @exception iaik.pkcs.PKCSException if the message cannot be recovered
   * @exception IOException if an I/O error occurs
   */
  public byte[] getPKCS7EncryptedDataStream(byte[] encoding, char[] password) 
    throws iaik.pkcs.PKCSException, IOException {

    // create the EncryptpedData object from a DER encoded byte array
    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    iaik.pkcs.pkcs7.EncryptedDataStream encrypted_data = new iaik.pkcs.pkcs7.EncryptedDataStream(is);

    System.out.println("Information about the encrypted data:");
    iaik.pkcs.pkcs7.EncryptedContentInfoStream eci = (iaik.pkcs.pkcs7.EncryptedContentInfoStream)encrypted_data.getEncryptedContentInfo();
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
      throw new iaik.pkcs.PKCSException("Key error: "+ex.toString());
    } catch (NoSuchAlgorithmException ex) {
      throw new iaik.pkcs.PKCSException("Content encryption algorithm not implemented: "+ex.getMessage());
    } catch (InvalidAlgorithmParameterException ex) {
      throw new iaik.pkcs.PKCSException("Invalid Parameters: "+ex.toString());
    } catch (InvalidParameterSpecException ex) {
      throw new iaik.pkcs.PKCSException("Invalid Parameters: "+ex.toString());
    }
  }

  /**
   * Creates a PKCS#7 <code>EncryptedData</code> message.
   * <p>
   * The supplied content is PBE-encrypted using the specified password.
   *
   * @param message the message to be encrypted, as byte representation
   * @param pbeAlgorithm the PBE algorithm to be used
   * @param password the password
   * @return the DER encoding of the <code>EncryptedData</code> object just created
   * @exception iaik.pkcs.PKCSException if the <code>EncryptedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public ASN1Object createPKCS7EncryptedData(byte[] message, AlgorithmID pbeAlgorithm, char[] password) 
    throws iaik.pkcs.PKCSException, IOException {

    iaik.pkcs.pkcs7.EncryptedData encrypted_data;

    try {
      encrypted_data = new iaik.pkcs.pkcs7.EncryptedData(message);
      // encrypt the message
      encrypted_data.setupCipher(pbeAlgorithm, password);
    } catch (InvalidKeyException ex) {
      throw new iaik.pkcs.PKCSException("Key error: "+ex.toString());
    } catch (NoSuchAlgorithmException ex) {
      throw new iaik.pkcs.PKCSException("Content encryption algorithm not implemented: "+ex.getMessage());
    }
    return encrypted_data.toASN1Object();

  }

  /**
   * Decrypts the PBE-encrypted content of the given PKCS#7 <code>EncryptedData</code> object
   * using the specified password and returns the decrypted (= original) message.
   *
   * @param asn1Object the <code>EncryptedData</code> object as ASN1Object
   * @param password the password to decrypt the message
   *
   * @return the recovered message, as byte array
   * @exception iaik.pkcs.PKCSException if the message cannot be recovered
   * @exception IOException if an I/O error occurs
   */
  public byte[] getPKCS7EncryptedData(ASN1Object asn1Object, char[] password) 
    throws iaik.pkcs.PKCSException, IOException {

    // create an EncryptedData from the ASN1Object
    iaik.pkcs.pkcs7.EncryptedData encrypted_data = new iaik.pkcs.pkcs7.EncryptedData(asn1Object);

    System.out.println("Information about the encrypted data:");
    iaik.pkcs.pkcs7.EncryptedContentInfo eci = (iaik.pkcs.pkcs7.EncryptedContentInfo)encrypted_data.getEncryptedContentInfo();
    System.out.println("Content type: "+eci.getContentType().getName());
    System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());

    // decrypt the message
    try {
      encrypted_data.setupCipher(password);
      return encrypted_data.getContent();

    } catch (InvalidKeyException ex) {
      throw new iaik.pkcs.PKCSException("Key error: "+ex.toString());
    } catch (NoSuchAlgorithmException ex) {
      throw new iaik.pkcs.PKCSException("Content encryption algorithm not implemented: "+ex.getMessage());
    } catch (InvalidAlgorithmParameterException ex) {
      throw new iaik.pkcs.PKCSException("Invalid Parameters: "+ex.toString());
    } catch (InvalidParameterSpecException ex) {
      throw new iaik.pkcs.PKCSException("Invalid Parameters: "+ex.toString()); 
    }
  }


  /**
   * Starts the tests.
   */
  public void start() {
     // the test message
    String m = "This is the test message.";
    System.out.println("Test message: \""+m+"\"");
    System.out.println();
    byte[] message = m.getBytes();

    try {
      byte[] data;
      byte[] received_message = null;
      System.out.println("Stream implementation demos");
      System.out.println("===========================");


      //
      // test CMS EncryptedDataStream
      //
      System.out.println("\nEncryptedDataStream demo [create]:\n");
      data = createEncryptedDataStream(message, (AlgorithmID)AlgorithmID.pbeWithSHAAnd3_KeyTripleDES_CBC.clone(), "password".toCharArray());
      // transmit data
      System.out.println("\nEncryptedDataStream demo [parse]:\n");
      received_message = getEncryptedDataStream(data, "password".toCharArray());
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));

      System.out.println("Testing compatibility to PKCS#7...");
      
      System.out.println("\nCMS EncryptedDataStream demo [create]:\n");
      data = createEncryptedDataStream(message, (AlgorithmID)AlgorithmID.pbeWithSHAAnd3_KeyTripleDES_CBC.clone(), "password".toCharArray());
      // transmit data
      System.out.println("\nPKCS#7 EncryptedDataStream demo [parse]:\n");
      received_message = getPKCS7EncryptedDataStream(data, "password".toCharArray());
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));
      
      System.out.println("\nPKCS7 EncryptedDataStream demo [create]:\n");
      data = createPKCS7EncryptedDataStream(message, (AlgorithmID)AlgorithmID.pbeWithSHAAnd3_KeyTripleDES_CBC.clone(), "password".toCharArray());
      // transmit data
      System.out.println("\nCMS EncryptedDataStream demo [parse]:\n");
      received_message = getEncryptedDataStream(data, "password".toCharArray());
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));


      // the non-stream implementation
      System.out.println("\nNon-stream implementation demos");
      System.out.println("===============================");

      ASN1Object obj = null;


      //
      // test CMS EncryptedData
      //
      System.out.println("\nEncryptedData demo [create]:\n");
      obj = createEncryptedData(message, (AlgorithmID)AlgorithmID.pbeWithSHAAnd3_KeyTripleDES_CBC.clone(), "password".toCharArray());
      // transmit data
      System.out.println("\nEncryptedData demo [parse]:\n");
      received_message = getEncryptedData(obj, "password".toCharArray());
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));
      
      System.out.println("Testing compatibility to PKCS#7...");
      
      System.out.println("\nCMS EncryptedData demo [create]:\n");
      obj = createEncryptedData(message, (AlgorithmID)AlgorithmID.pbeWithSHAAnd3_KeyTripleDES_CBC.clone(), "password".toCharArray());
      // transmit data
      System.out.println("\nPKCS#7 EncryptedData demo [parse]:\n");
      received_message = getPKCS7EncryptedData(obj, "password".toCharArray());
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));
      
      System.out.println("\nPKCS#7 EncryptedData demo [create]:\n");
      obj = createPKCS7EncryptedData(message, (AlgorithmID)AlgorithmID.pbeWithSHAAnd3_KeyTripleDES_CBC.clone(), "password".toCharArray());
      // transmit data
      System.out.println("\nCMS EncryptedData demo [parse]:\n");
      received_message = getEncryptedData(obj, "password".toCharArray());
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));

   	} catch (Exception ex) {
   	  ex.printStackTrace();
   	  throw new RuntimeException(ex.toString());
   	}
  }

  /**
   * Tests the IAIK CMS against the IAIK PKCS#7 EncryptedData(Stream) implementation.
   */
  public static void main(String argv[]) throws Exception {

    DemoUtil.initDemos();

    (new PKCS7CMSEncryptedDataDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
