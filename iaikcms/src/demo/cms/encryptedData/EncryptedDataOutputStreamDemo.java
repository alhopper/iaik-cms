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
// $Header: /IAIK-CMS/current/src/demo/cms/encryptedData/EncryptedDataOutputStreamDemo.java 6     23.08.13 14:22 Dbratko $
// $Revision: 6 $
//


package demo.cms.encryptedData;

import iaik.asn1.CodingException;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.cms.CMSException;
import iaik.cms.ContentInfoOutputStream;
import iaik.cms.EncryptedContentInfoStream;
import iaik.cms.EncryptedDataOutputStream;
import iaik.cms.EncryptedDataStream;
import iaik.cms.attributes.CMSContentType;
import iaik.security.random.SecRandom;
import iaik.utils.CryptoUtils;
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
 * Demonstrates the usage of class {@link iaik.cms.EncryptedDataOutputStream} for
 * PBE encrypting data using the CMS type EnryptedData.
 * 
 * @author Dieter Bratko
 */
public class EncryptedDataOutputStreamDemo {

  // secure random number generator
  SecureRandom random;

  /**
   * Default constructor.
   */
  public EncryptedDataOutputStreamDemo() {
    
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                    EncryptedDataOutputStream demo                              *");
    System.out.println("*    (shows the usage of the CMS EncryptedDataOutputStream implementation)       *");
    System.out.println("**********************************************************************************");
    System.out.println();
    
    random = SecRandom.getDefault();

  }


  /**
   * Creates a CMS <code>EncryptedData</code> and wraps it into a ContentInfo.
   *
   * @param message the message to be encrypted, as byte representation
   * @return the encoded EncryptedData object just created, wrapped into a ContentInfo
   *
   * @exception CMSException if the <code>EncryptedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createEncryptedData(byte[] message, char[] password) throws CMSException, IOException {
    
    
    //  a stream from which to read the data to be encrypted
    ByteArrayInputStream is = new ByteArrayInputStream(message);
    
    // the stream to which to write the EncryptedData
    ByteArrayOutputStream resultStream = new ByteArrayOutputStream();
    
    //  wrap EncryptedData into a ContentInfo 
    ContentInfoOutputStream contentInfoStream = 
      new ContentInfoOutputStream(ObjectID.cms_encryptedData, resultStream);
    
    // create a new EncryptedData object 
    EncryptedDataOutputStream  encryptedData = new EncryptedDataOutputStream(contentInfoStream);
    // setup cipher for encryption
    AlgorithmID contentEncAlg = (AlgorithmID)AlgorithmID.pbeWithSHAAnd3_KeyTripleDES_CBC.clone();
    try {
      encryptedData.setupCipher(contentEncAlg, password, 2000);
    } catch (InvalidKeyException ex) {
      throw new CMSException("Cannot setup cipher for encryption: " + ex.toString());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Cannot setup cipher for encryption: " + ex.toString());  
    }
    Attribute[] attributes = new Attribute[1];
    try {
      // just for demonstration: set some unprotected attribute
      // content type is data
      CMSContentType contentType = new CMSContentType(ObjectID.cms_data);
      attributes[0] = new Attribute(contentType);
      encryptedData.setUnprotectedAttributes(attributes);
    } catch (Exception ex) {
      throw new CMSException("Error creating attribute: " + ex.toString());   
    }  

    int blockSize = 8; // in real world we would use a block size like 2048
    //  write in the data to be encrypted
    byte[] buffer = new byte[blockSize];
    int bytesRead;
    while ((bytesRead = is.read(buffer)) != -1) {
      encryptedData.write(buffer, 0, bytesRead);
    }
    
    // closing the stream finishes encryption and closes the underlying stream
    encryptedData.close();
    return resultStream.toByteArray();
  }

  /**
   * Decrypts the encrypted content of the given EncryptedData object.
   *
   * @param encoding the encoded EncryptedData object, wrapped in a ContentInfo
   * @param password the password to decrypt the message
   *
   * @return the recovered message, as byte array
   * 
   * @exception CMSException if the message cannot be recovered
   * @exception IOException if an I/O error occurs
   */
  public byte[] getEncryptedData(byte[] encoding, char[] password) throws CMSException, IOException {

    //  create the EncryptpedData object from a BER encoded byte array
    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    EncryptedDataStream encryptedData = new EncryptedDataStream(is);

    System.out.println("Information about the encrypted data:");
    EncryptedContentInfoStream eci = encryptedData.getEncryptedContentInfo();
    System.out.println("Content type: "+eci.getContentType().getName());
    System.out.println("Content encryption algorithm: "+eci.getContentEncryptionAlgorithm().getName());

    byte[] content = null;
    // decrypt the message
    try {
      encryptedData.setupCipher(password);
      InputStream decrypted = encryptedData.getInputStream();
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      Util.copyStream(decrypted, os, null);
      content = os.toByteArray();

      // get any unprotected attributes:
      Attribute[] attributes = encryptedData.getUnprotectedAttributes();
      if ((attributes != null) && (attributes.length > 0)) {
        System.out.println("Attributes included: ");
        // we know we have used content type
        CMSContentType contentType = (CMSContentType)attributes[0].getAttributeValue();
        System.out.println(contentType);  
      }  

    } catch (InvalidKeyException ex) {
      throw new CMSException("Key error: " + ex.toString());
    } catch (NoSuchAlgorithmException ex) {
      throw new CMSException("Content encryption algorithm not implemented: " + ex.toString());
    } catch (InvalidAlgorithmParameterException ex) {
      throw new CMSException("Invalid Parameters: " + ex.toString());
    } catch (InvalidParameterSpecException ex) {
      throw new CMSException("Content encryption algorithm not implemented: " + ex.toString());
    } catch (CodingException ex) {
      throw new CMSException("Error decoding attributes: " + ex.toString());
    }
    
    return content;
  }

  /**
   * Starts the demo.
   */
  public void start() {
     // the test message
    String m = "This is the test message.";
    System.out.println("Test message: \""+m+"\"");
    System.out.println();
    byte[] message = m.getBytes();
    
    // password (in real world use some more secure password)
    char[] password = { 't', 'o', 'p', '-', 's', 'e', 'c', 'r', 'e', 't', '!' };

    try {
      byte[] encoding;
      byte[] received_message = null;
      System.out.println("EnvelopedOutputStream implementation demo");
      System.out.println("===========================");


      //
      // test CMS EncryptedDataOutputStream
      //
      System.out.println("\nEncryptedDataStream demo [create]:\n");
      encoding = createEncryptedData(message, password);
      // transmit data
      System.out.println("\nEncryptedDataStream demo [parse]:\n");
      received_message = getEncryptedData(encoding, password);
      System.out.print("\nDecrypted content: ");
      System.out.println(new String(received_message));

      if (CryptoUtils.equalsBlock(received_message, message) == false) {
        throw new Exception("Decrypted content not equal to original one!");
      }
      System.out.println("Ready!");

    } catch (Exception ex) {
      ex.printStackTrace();
      throw new RuntimeException(ex.toString());
    } finally {
      if (password != null) {
        for (int i = 0; i < password.length; i++) {
          password[i] = '\u0000';
        }
      }
    } 
  }


  /**
   * Main method.
   *
   * @exception Exception
   *            if an some error occurs 
   */
  public static void main(String argv[]) throws Exception {

    demo.DemoUtil.initDemos();

    (new EncryptedDataOutputStreamDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
