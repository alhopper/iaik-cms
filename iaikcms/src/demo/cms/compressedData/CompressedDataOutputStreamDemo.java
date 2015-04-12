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
// $Header: /IAIK-CMS/current/src/demo/cms/compressedData/CompressedDataOutputStreamDemo.java 8     23.08.13 14:20 Dbratko $
// $Revision: 8 $
//

package demo.cms.compressedData;

import iaik.asn1.structures.AlgorithmID;
import iaik.cms.CMSAlgorithmID;
import iaik.cms.CMSException;
import iaik.cms.CompressedDataOutputStream;
import iaik.cms.CompressedDataStream;
import iaik.cms.ContentInfoOutputStream;
import iaik.utils.CryptoUtils;
import iaik.utils.Util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;

import demo.DemoUtil;

/**
 * Demonstrates the usage of class {@link iaik.cms.CompressedDataOutputStream} and
 * {@link iaik.cms.CompressedDataOutputStream} for compressing data using
 * the CMS type CompressedData.
 * 
 * @see iaik.cms.CompressedDataOutputStream
 * @see iaik.cms.CompressedDataStream
 * 
 * @author Dieter Bratko 
 */
public class CompressedDataOutputStreamDemo {
  
  /**
   * Default constructor.
   */
  public CompressedDataOutputStreamDemo() {
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                        CompressedDataOutputStream demo                         *");
    System.out.println("*  (shows the usage of the CMS CompressedDataOutputStream type implementation)   *");
    System.out.println("**********************************************************************************");
    System.out.println();
  }


  /**
   * Uses the IAIK-CMS CompressedDataOutputStream class to create a CMS 
   * <code>CompressedData</code> object for compressing the given message.
   * <p>
   * @param message the message to be compressed, as byte representation
   *
   * @return the BER encoding of the <code>CompressedData</code> object just created
   *
   * @exception CMSException if the <code>CompressedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   * @exception NoSuchAlgorithmException if the compression algorithm is not supported
   */
  public byte[] createCompressedData(byte[] message) throws CMSException, IOException {

    System.out.println("Create a new CompressedData message.");

    // the stream from which to read the data to be compressed
    ByteArrayInputStream is = new ByteArrayInputStream(message);
    
    // the stream to which to write the CompressedData
    ByteArrayOutputStream resultStream = new ByteArrayOutputStream();
    
    // wrap CompressedData into a ContentInfo 
    ContentInfoOutputStream contentInfoStream = 
      new ContentInfoOutputStream(CompressedDataStream.contentType, resultStream);
    // create a new CompressedDataOutputStream  
    CompressedDataOutputStream compressedData = 
      new CompressedDataOutputStream(contentInfoStream,
                                     (AlgorithmID)CMSAlgorithmID.zlib_compress.clone());

    int blockSize = 8; // in real world we would use a block size like 2048
    //  write in the data to be compressed
    byte[] buffer = new byte[blockSize];
    int bytesRead;
    while ((bytesRead = is.read(buffer)) != -1) {
      compressedData.write(buffer, 0, bytesRead);
    }
    
    // closing the stream finishes encoding and closes the underlying stream
    compressedData.close();
    return resultStream.toByteArray();
  }

  /**
   * Parses a CMS <code>CompressedData</code> object.
   *
   * @param encoding  the <code>CompressedData</code> object as BER encoded byte array
   *
   * @return the decompressed message as byte array
   *
   * @exception CMSException if the CompressedData cannot be parsed
   * @exception IOException if an I/O error occurs
   * @exception NoSuchAlgorithmException if the compression algorithm is not supported
   */
  public byte[] getCompressedData(byte[] encoding) 
    throws CMSException, IOException, NoSuchAlgorithmException {

    System.out.println("Parse CompressedData message.");
    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(encoding);
    // create the CompressedData object
    CompressedDataStream compressedData = new CompressedDataStream(is);
 
    // get an InputStream for reading and decompressing the content
    InputStream data = compressedData.getInputStream();
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    Util.copyStream(data, os, null);
  
    return os.toByteArray();
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
   
      System.out.println("\nCreating compressed message\n");
      encoding = createCompressedData(message);
      // transmit data
      System.out.println("\nParsing compressed data\n");
      receivedMessage = getCompressedData(encoding);
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

    (new CompressedDataOutputStreamDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
