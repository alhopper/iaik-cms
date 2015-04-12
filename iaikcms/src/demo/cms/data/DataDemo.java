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
// $Header: /IAIK-CMS/current/src/demo/cms/data/DataDemo.java 16    23.08.13 14:20 Dbratko $
// $Revision: 16 $
//

package demo.cms.data;

import iaik.cms.CMSException;
import iaik.cms.Data;
import iaik.cms.DataStream;
import iaik.utils.Util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import demo.DemoUtil;



/**
 * Shows the usage of the IAIK-CMS Data(Stream) implementation.
 * 
 * @author Dieter Bratko 
 */
public class DataDemo {

 
  /**
   * Default constructor.
   */
  public DataDemo() {
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                                  DataDemo                                      *");
    System.out.println("*             (shows the usage of the CMS Data type implementation)              *");
    System.out.println("**********************************************************************************");
    System.out.println();

  }
  
  /**
   * Creates a CMS <code>Data</code> object.
   * <p>
   * @param message the message to be sent, as byte representation
   * @return the BER encoding of the <code>Data</code> object just created
   * @exception CMSException if the <code>Data</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createDataStream(byte[] message) throws CMSException, IOException  {

    System.out.println("Create a new Data message:");

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);

    // create a new Data object which includes the data
    DataStream data = new DataStream(is, 2048);


    // return the Data as BER encoded byte array with block size 2048
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    data.writeTo(os);
    return os.toByteArray();
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
  public byte[] getDataStream(byte[] data) throws CMSException, IOException {

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
   * Creates a CMS <code>Data</code> object.
   * <p>
   * @param message the message to be sent, as byte representation
   * @return the the DER encoded <code>Data</code> object just created
   * @exception CMSException if the <code>Data</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createData(byte[] message) throws CMSException, IOException  {

    System.out.println("Create a new Data message:");

    // create a new DigestedData object which includes the data
    Data data = new Data(message);
    // return the ASN.1 representation
    return data.getEncoded();
  }

  /**
   * Parses a CMS <code>Data</code> object.
   *
   * @param encoding the DER encoded <code>Data</code> object
   *
   * @return the inherent content as byte array
   *
   * @exception CMSException if an parsing exception occurs
   * @exception IOException if an I/O error occurs
   */
  public byte[] getData(byte[] encoding) throws CMSException, IOException {

    // create the Data object
    Data data = new Data(new ByteArrayInputStream(encoding));

    // get and return the content
    return data.getData();
  }
  
 
  /**
   * Tests IAIK CMS Data(Stream).
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

      // the stream implementation
      //
      // test CMS DataStream
      //
      System.out.println("\nDataStream demo [create]:\n");
      encoding = createDataStream(message);
      // transmit data
      System.out.println("\nDataStream demo [parse]:\n");
      received_message = getDataStream(encoding);
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));
      
     
      // the non-stream implementation
      System.out.println("\nNon-stream implementation demos");
      System.out.println("===============================");

      //
      // test CMS Data
      //
     
      System.out.println("\nData demo [create]:\n");
      encoding = createData(message);
      // transmit data
      System.out.println("\nData demo [parse]:\n");

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

   	(new DataDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
