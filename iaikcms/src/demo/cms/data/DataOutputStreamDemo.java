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
// $Header: /IAIK-CMS/current/src/demo/cms/data/DataOutputStreamDemo.java 4     23.08.13 14:20 Dbratko $
// $Revision: 4 $
//

package demo.cms.data;

import iaik.asn1.ObjectID;
import iaik.cms.CMSException;
import iaik.cms.ContentInfoOutputStream;
import iaik.cms.DataOutputStream;
import iaik.cms.DataStream;
import iaik.utils.Util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import demo.DemoUtil;

/**
 * Demonstrates the usage of class {@link iaik.cms.DataOutputStream}.
 * 
 * @author Dieter Bratko 
 */
public class DataOutputStreamDemo {

  /**
   * Default constructor.
   */
  public DataOutputStreamDemo() throws IOException {
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                          DataOutputStream demo                                 *");
    System.out.println("*           (shows the usage of the DataOutputStream implementation)             *");
    System.out.println("**********************************************************************************");
    System.out.println();
  }


  /**
   * Uses the IAIK-CMS DataOutputStream class to encode the given data.
   * 
   * @param message the message to be encoded, as byte representation
   * 
   * @return the BER encoding of the <code>Data</code> object just created,
   *         wrapped in a ContentInfo
   * 
   * @exception CMSException if the <code>Data</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createData(byte[] message) throws CMSException, IOException  {

    System.out.println("Create a new Data message:");

    // the stream from which to read the content
    ByteArrayInputStream is = new ByteArrayInputStream(message);

    // the stream to which to write the Data object
    ByteArrayOutputStream resultStream = new ByteArrayOutputStream();
    
    // wrap Data into a ContentInfo 
    ContentInfoOutputStream contentInfoStream = 
      new ContentInfoOutputStream(ObjectID.cms_data, resultStream);
    // create a new DataOutputStream object 
    DataOutputStream data = new DataOutputStream(contentInfoStream);


    int blockSize = 8; // in real world we would use a block size like 2048
    //  write the data 
    byte[] buffer = new byte[blockSize];
    int bytesRead;
    while ((bytesRead = is.read(buffer)) != -1) {
      data.write(buffer, 0, bytesRead);
    }
    
    // closing the stream 
    data.close();
    return resultStream.toByteArray();
  }

  /**
   * Parses a CMS <code>Data</code> object.
   *
   * @param data the <code>Data</code> object as BER encoded byte array
   *
   * @return the inherent content as byte array
   *
   * @exception CMSException if an parsing exception occurs
   * @exception IOException if an I/O error occurs
   */
  public byte[] getData(byte[] data) throws CMSException, IOException {

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(data);
    // create the Data object
    DataStream dataStream = new DataStream(is);

    // get an InputStream for reading the signed content
    InputStream content = dataStream.getInputStream();
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    Util.copyStream(content, os, null);

    return os.toByteArray();
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
      
      System.out.println("\nDataOutputStream demo [create]:\n");
      encoding = createData(message);
      // transmit data
      System.out.println("\nDataOutputStream demo [parse]:\n");
      received_message = getData(encoding);
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));

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

    (new DataOutputStreamDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
