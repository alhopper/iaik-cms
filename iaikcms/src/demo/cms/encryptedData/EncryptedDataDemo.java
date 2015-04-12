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
// $Header: /IAIK-CMS/current/src/demo/cms/encryptedData/EncryptedDataDemo.java 15    23.08.13 14:22 Dbratko $
// $Revision: 15 $
//

package demo.cms.encryptedData;

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
 * Demonstrates the usage of class {@link iaik.cms.EncryptedDataStream} and
 * {@link iaik.cms.EncryptedData} for encrypting data using the CMS type
 * EncryptedData.
 * 
 * @author Dieter Bratko
 */
public class EncryptedDataDemo {

  // secure random number generator
  SecureRandom random;

  /**
   * Default constructor.
   */
  public EncryptedDataDemo() {
    
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                           EncryptedDataDemo demo                               *");
    System.out.println("*        (shows the usage of the CMS EncryptedData type implementation)          *");
    System.out.println("**********************************************************************************");
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
    // create a new EncryptedData object encrypted with TripleDES CBC
    try {
      encrypted_data = new EncryptedDataStream(is, 2048);
      encrypted_data.setupCipher(pbeAlgorithm, password);
    } catch (InvalidKeyException ex) {
      throw new CMSException("Key error: "+ex.getMessage());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.getMessage());
    }

    // return the EncryptedData as DER encoded byte array with block size 2048
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
      throw new CMSException("Key error: "+ex.getMessage());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.getMessage());
    } catch (InvalidAlgorithmParameterException ex) {
      throw new CMSException("Invalid Parameters: "+ex.getMessage());
    } catch (InvalidParameterSpecException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.getMessage());
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
  public byte[] createEncryptedData(byte[] message, AlgorithmID pbeAlgorithm, char[] password) throws CMSException, IOException {

    EncryptedData encrypted_data;

    try {
      encrypted_data = new EncryptedData(message);
      // encrypt the message
      encrypted_data.setupCipher(pbeAlgorithm, password);
    } catch (InvalidKeyException ex) {
      throw new CMSException("Key error: "+ex.getMessage());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.getMessage());
    }
    return encrypted_data.getEncoded();

  }

  /**
   * Decrypts the PBE-encrypted content of the given CMS <code>EncryptedData</code> object
   * using the specified password and returns the decrypted (= original) message.
   *
   * @param encoding the DER encoded <code>EncryptedData</code> object
   * @param password the password to decrypt the message
   *
   * @return the recovered message, as byte array
   * @exception CMSException if the message cannot be recovered
   * @exception IOException if an I/O error occurs
   */
  public byte[] getEncryptedData(byte[] encoding, char[] password) throws CMSException, IOException {

    // create an EncryptedData from the ASN1Object
    EncryptedData encrypted_data = new EncryptedData(new ByteArrayInputStream(encoding));

    System.out.println("Information about the encrypted data:");
    EncryptedContentInfo eci = (EncryptedContentInfo)encrypted_data.getEncryptedContentInfo();
    System.out.println("Content type: "+eci.getContentType().getName());
    System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());

    // decrypt the message
    try {
      encrypted_data.setupCipher(password);
      return encrypted_data.getContent();

    } catch (InvalidKeyException ex) {
      throw new CMSException("Key error: "+ex.getMessage());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.getMessage());
    } catch (InvalidAlgorithmParameterException ex) {
      throw new CMSException("Invalid Parameters: "+ex.getMessage());
    } catch (InvalidParameterSpecException ex) {
      throw new CMSException("Content encryption algorithm not implemented: "+ex.getMessage());
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
      byte[] encoding;
      byte[] received_message = null;
      System.out.println("Stream implementation demos");
      System.out.println("===========================");


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



      // the non-stream implementation
      System.out.println("\nNon-stream implementation demos");
      System.out.println("===============================");

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

   	} catch (Exception ex) {
   	  ex.printStackTrace();
   	  throw new RuntimeException(ex.toString());
   	}
  }

  /**
   * Maim method.
   */
  public static void main(String argv[]) throws Exception {

    DemoUtil.initDemos();

    (new EncryptedDataDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
