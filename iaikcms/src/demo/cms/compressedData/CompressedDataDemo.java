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
// $Header: /IAIK-CMS/current/src/demo/cms/compressedData/CompressedDataDemo.java 11    23.08.13 14:20 Dbratko $
// $Revision: 11 $
//

package demo.cms.compressedData;

import iaik.asn1.structures.AlgorithmID;
import iaik.cms.CMSAlgorithmID;
import iaik.cms.CMSException;
import iaik.cms.CompressedData;
import iaik.cms.CompressedDataStream;
import iaik.cms.ContentInfo;
import iaik.cms.ContentInfoStream;
import iaik.cms.Utils;
import iaik.utils.CryptoUtils;
import iaik.utils.Util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;

import demo.DemoUtil;



/**
 * Demonstrates the usage of class {@link iaik.cms.CompressedDataStream} and
 * {@link iaik.cms.CompressedData} for compressing/decompressing data using
 * the CMS type CompressedData.
 * 
 * @author Dieter Bratko   
 */
public class CompressedDataDemo {
  
  /**
   * In explcit mode the compressed content data has to be transmitted by other means.
   */
  byte[] compressedContent_;

  /**
   * Default constructor.
   */
  public CompressedDataDemo() {
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                             CompressedDataDemo                                 *");
    System.out.println("*        (shows the usage of the CMS CompressedData type implementation)         *");
    System.out.println("**********************************************************************************");
    System.out.println();
  }


  /**
   * Creates a CMS <code>CompressedData</code> object.
   * <p>
   * @param message the message to be compressed, as byte representation
   * @param mode IMPLICIT (include compressed content) or 
   *             EXPLICIT (do not include compressed content)
   *
   * @return the BER encoding of the <code>CompressedData</code> object just created
   *
   * @exception CMSException if the <code>CompressedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   * @exception NoSuchAlgorithmException if the compression algorithm is not supported
   */
  public byte[] createCompressedDataStream(byte[] message, int mode) 
    throws CMSException, IOException, NoSuchAlgorithmException {

    System.out.println("Create a new CompressedData message.");

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);

    // create a new CompressedData object 
    CompressedDataStream compressedData = new CompressedDataStream(is, 
                                                                   (AlgorithmID)CMSAlgorithmID.zlib_compress.clone(),
                                                                   mode);


    // in explicit mode transmit compressed content out-of-band 
    if (mode == CompressedDataStream.EXPLICIT) {
      InputStream dataIs = compressedData.getInputStream();
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      Utils.copyStream(dataIs, baos, null);
      compressedContent_ = baos.toByteArray();
    }

    // for testing return the CompressedData as BER encoded byte array with block size of 4
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    compressedData.setBlockSize(4);
    ContentInfoStream cis = new ContentInfoStream(compressedData);
    cis.writeTo(os);
    return os.toByteArray();
  }

  /**
   * Parses a CMS <code>CompressedData</code> object.
   *
   * @param encoding  the <code>CompressedData</code> object as BER encoded byte array
   * @param compressedContent the compressed content which was transmitted out-of-band
   *
   * @return the decompressed message as byte array
   *
   * @exception CMSException if the CompressedData cannot be parsed
   * @exception IOException if an I/O error occurs
   * @exception NoSuchAlgorithmException if the compression algorithm is not supported
   */
  public byte[] getCompressedDataStream(byte[] encoding, byte[] compressedContent) 
    throws CMSException, IOException, NoSuchAlgorithmException {

    System.out.println("Parse CompressedData message.");
    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    // create the CompressedData object
    CompressedDataStream compressedData = new CompressedDataStream(is);
    
    if (compressedData.getMode() == CompressedDataStream.EXPLICIT) {
      // in explicit mode now provide the content received by other means
      compressedData.setInputStream(new ByteArrayInputStream(compressedContent));
    }

    // get an InputStream for reading and decompressing the content
    InputStream data = compressedData.getInputStream();
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    Util.copyStream(data, os, null);
  
    return os.toByteArray();
  }


  /**
   * Creates a CMS <code>CompressedData</code> object.
   * <p>
   *
   * @param message the message to be compressed, as byte representation
   * @param mode IMPLICIT (include the compressed content) or 
   *             EXPLICIT (do not include the compressed content)
   *
   * @return the DER encoded <code>CompressedData</code>
   *
   * @exception CMSException if the <code>CompressedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   * @exception NoSuchAlgorithmException if the compression algorithm is not supported
   */
  public byte[] createCompressedData(byte[] message, int mode)
    throws CMSException, IOException, NoSuchAlgorithmException {

    System.out.println("Create a new CompressedData message.");

    // create a new CompressedData object 
    CompressedData compressedData = new CompressedData(message, 
                                                      (AlgorithmID)CMSAlgorithmID.zlib_compress.clone(),
                                                       mode);
    // in explicit mode get the compressed content to transmit it by other means
    if (mode == CompressedData.EXPLICIT) {
      compressedContent_ = compressedData.getContent();
    }
    ContentInfo ci = new ContentInfo(compressedData);
    return ci.getEncoded();
  }

  /**
   * Parses a CMS <code>CompressedData</code> object.
   *
   * @param encoding the DER encoded <code>CompressedData</code> object 
   * @param compressedContent the compressed content which was transmitted out-of-band
   *
   * @return the decompressed message as byte array
   *
   * @exception CMSException if the CompressedData cannot be parsed
   * @exception IOException if an I/O error occurs
   * @exception NoSuchAlgorithmException if the compression algorithm is not supported
   */
  public byte[] getCompressedData(byte[] encoding, byte[] compressedContent) 
    throws CMSException, IOException, NoSuchAlgorithmException {
    
    System.out.println("Parse CompressedData message.");
    ByteArrayInputStream encodedStream = new ByteArrayInputStream(encoding);
    // create the CompressedData object
    CompressedData compressedData = new CompressedData(encodedStream);
    
    if (compressedData.getMode() == CompressedData.EXPLICIT) {
      // in explicit mode provide the compressed content received by other means
      compressedData.setContent(compressedContent);
    }
    // decompress
    return compressedData.getContent();
  }
  
  /**
   * Starts the demo.
   */
  public void start() {
     // the test message
    String m = "ABABABABABABABBABABABABABABABBABABABABABABABBAABABABABABA.";
    System.out.println("Test message: \""+m+"\"");
    System.out.println();
    byte[] message = m.getBytes();

    try {
      byte[] encoding;
      byte[] receivedMessage = null;
      System.out.println("Stream implementation demos");
      System.out.println("===========================");

      // the stream implementation
   
      //
      // test CMS Implicit CompressedDataStream
      //
      System.out.println("\nImplicit CompressedDataStream demo [create]\n");
      encoding = createCompressedDataStream(message, CompressedDataStream.IMPLICIT);
      // transmit data
      System.out.println("\nImplicit CompressedDataStream demo [parse]\n");
      receivedMessage = getCompressedDataStream(encoding, null);
      if (CryptoUtils.equalsBlock(message, receivedMessage) == false) {
        throw new CMSException("Decompression error!");
      }  
      System.out.print("\nContent: ");
      System.out.println(new String(receivedMessage));

      //
      // test CMS Explicit CompressedDataStream
      //
      System.out.println("\nExplicit CompressedDataStream demo [create]\n");
      encoding = createCompressedDataStream(message, CompressedDataStream.EXPLICIT);
      // transmit data
      System.out.println("\nExplicit CompressedDataStream demo [parse]\n");
      receivedMessage = getCompressedDataStream(encoding, compressedContent_);
      if (CryptoUtils.equalsBlock(message, receivedMessage) == false) {
        throw new CMSException("Decompression error!");
      } 
      System.out.print("\nContent: ");
      System.out.println(new String(receivedMessage));
      
      // the non-stream implementation
      System.out.println("\nNon-stream implementation demos");
      System.out.println("===============================");

      //
      // test CMS Implicit CompressedData
      //
      System.out.println("\nImplicit CompressedData demo [create]\n");
      encoding = createCompressedData(message, CompressedData.IMPLICIT);
      // transmit data
      System.out.println("\nImplicit CompressedData demo [parse]\n");
      receivedMessage = getCompressedData(encoding, null);
      if (CryptoUtils.equalsBlock(message, receivedMessage) == false) {
        throw new CMSException("Decompression error!");
      } 
      System.out.print("\nContent: ");
      System.out.println(new String(receivedMessage));

      //
      // test CMS Explicit CompressedData
      //
      System.out.println("\nExplicit CompressedData demo [create]\n");
      encoding = createCompressedData(message, CompressedData.EXPLICIT);
      // transmit data
      System.out.println("\nExplicit CompressedData demo [parse]\n");
      receivedMessage = getCompressedData(encoding, compressedContent_);
      if (CryptoUtils.equalsBlock(message, receivedMessage) == false) {
        throw new CMSException("Decompression error!");
      } 
      System.out.print("\nContent: ");
      System.out.println(new String(receivedMessage));
      
   	} catch (Exception ex) {
   	  ex.printStackTrace();
   	  throw new RuntimeException(ex.toString());
   	}
  }

  /**
   * Main method.
   */
  public static void main(String argv[]) throws Exception {

   	DemoUtil.initDemos();

    (new CompressedDataDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
