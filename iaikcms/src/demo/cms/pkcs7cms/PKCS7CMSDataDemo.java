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
// $Header: /IAIK-CMS/current/src/demo/cms/pkcs7cms/PKCS7CMSDataDemo.java 14    23.08.13 14:27 Dbratko $
// $Revision: 14 $
//

package demo.cms.pkcs7cms;

import iaik.asn1.ASN1Object;
import iaik.cms.CMSException;
import iaik.cms.Data;
import iaik.cms.DataStream;
import iaik.pkcs.PKCSException;
import iaik.utils.Util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import demo.DemoUtil;



/**
 * Tests IAIK CMS Data(Stream) against IAIK PKCS7 Data(Stream).
 * 
 * @author Dieter Bratko
 */
public class PKCS7CMSDataDemo {

 
  /**
   * Default constructor.
   */
  public PKCS7CMSDataDemo() {
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                                  PKCS7CMSDataDemo demo                         *");
    System.out.println("*   (tests the CMS Data against the IAIK-JCE PKCS#7 Data type implementation)    *");
    System.out.println("**********************************************************************************");
    System.out.println();
    
  }
  
  /**
   * Creates a CMS <code>Data</code> object.
   * <p>
   * @param message the message to be sent, as byte representation
   * @return the DER encoding of the <code>Data</code> object just created
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
   * @param data the <code>Data</code> object as DER encoded byte array
   *
   * @return the inherent message as byte array
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
   * @return the ASN.1 representation of the <code>Data</code> object just created
   * @exception CMSException if the <code>Data</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public ASN1Object createData(byte[] message) throws CMSException, IOException  {

    System.out.println("Create a new Data message:");

    // create a new DigestedData object which includes the data
    Data data = new Data(message);
    // return the ASN.1 representation
    return data.toASN1Object();
  }

  /**
   * Parses a CMS <code>Data</code> object.
   *
   * @param asn1Object the <code>Data</code> object as ASN.1 object
   *
   * @return the inherent message as byte array
   * @exception CMSException if an parsing exception occurs
   * @exception IOException if an I/O error occurs
   */
  public byte[] getData(ASN1Object asn1Object) throws CMSException, IOException {

    // create the Data object
    Data data = new Data(asn1Object);

    // get and return the content
    return data.getData();
  }
  
  // PKCS#7

  /**
   * Creates a PKCS#7 <code>Data</code> object.
   * <p>
   * @param message the message to be sent, as byte representation
   * @return the DER encoding of the <code>Data</code> object just created
   * @exception PKCSException if the <code>Data</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createPKCS7DataStream(byte[] message) 
    throws iaik.pkcs.PKCSException, IOException  {

    System.out.println("Create a new Data message:");

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);

    // create a new Data object which includes the data
    iaik.pkcs.pkcs7.DataStream data = new iaik.pkcs.pkcs7.DataStream(is, 2048);

    // return the Data as BER encoded byte array with block size 2048
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    data.writeTo(os);
    return os.toByteArray();
  }

  /**
   * Parses a PKCS#7 <code>Data</code> object.
   *
   * @param data the <code>Data</code> object as DER encoded byte array
   *
   * @return the inherent message as byte array, or <code>null</code> if there
   *         is no message included into the supplied <code>data</code>
   *         object
   * @exception PKCSException if an parsing exception occurs
   * @exception IOException if an I/O error occurs
   */
  public byte[] getPKCS7DataStream(byte[] data) throws iaik.pkcs.PKCSException, IOException {

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(data);
    // create the Data object
    iaik.pkcs.pkcs7.DataStream dataStream = new iaik.pkcs.pkcs7.DataStream(is);

    // get an InputStream for reading the signed content
    InputStream content = dataStream.getInputStream();
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    Util.copyStream(content, os, null);

    return os.toByteArray();
  }


  /**
   * Creates a PKCS#7 <code>Data</code> object.
   * <p>
   * @param message the message to be sent, as byte representation
   * @return the ASN.1 representation of the <code>Data</code> object just created
   * @exception PKCSException if the <code>Data</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public ASN1Object createPKCS7Data(byte[] message) throws iaik.pkcs.PKCSException, IOException  {

    System.out.println("Create a new Data message:");

    // create a new DigestedData object which includes the data
    iaik.pkcs.pkcs7.Data data = new iaik.pkcs.pkcs7.Data(message);
    // return the ASN.1 representation
    return data.toASN1Object();
  }

  /**
   * Parses a PKCS#7 <code>Data</code> object.
   *
   * @param asn1Object the <code>Data</code> object as ASN.1 object
   *
   * @return the inherent message as byte array
   * @exception PKCSException if an parsing exception occurs
   * @exception IOException if an IOException occurs
   */
  public byte[] getPKCS7Data(ASN1Object asn1Object) throws iaik.pkcs.PKCSException, IOException {

    // create the Data object
    iaik.pkcs.pkcs7.Data data = new iaik.pkcs.pkcs7.Data(asn1Object);

    // get and return the content
    return data.getData();
  }


  /**
   * Tests IAIK CMS Data(Stream) against IAIK PKCS7 Data(Stream).
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

      // the stream implementation
      //
      // test CMS DataStream
      //
      System.out.println("\nDataStream demo [create]:\n");
      data = createDataStream(message);
      // transmit data
      System.out.println("\nDataStream demo [parse]:\n");
      received_message = getDataStream(data);
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));
      
      System.out.println("Testing CMS against PKCS#7...\n");
      
      System.out.println("\nCMS DataStream demo [create]:\n");
      data = createDataStream(message);
      // transmit data
      System.out.println("\nPKCS7 DataStream demo [parse]:\n");
      received_message = getPKCS7DataStream(data);
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));
      
      System.out.println("\nPKCS#7 DataStream demo [create]:\n");
      data = createPKCS7DataStream(message);
      // transmit data
      System.out.println("\nCMS DataStream demo [parse]:\n");
      received_message = getDataStream(data);
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));

      // the non-stream implementation
      System.out.println("\nNon-stream implementation demos");
      System.out.println("===============================");

      //
      // test CMS Data
      //
      ASN1Object obj = null;

      System.out.println("\nData demo [create]:\n");
      obj = createData(message);
      // transmit data
      System.out.println("\nData demo [parse]:\n");

      received_message = getData(obj);
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));
      
      System.out.println("Testing CMS against PKCS#7...\n");
      
      System.out.println("\nCMS Data demo [create]:\n");
      obj = createData(message);
      // transmit data
      System.out.println("\nPKCS#7 Data demo [parse]:\n");

      received_message = getPKCS7Data(obj);
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));
      
      System.out.println("\nPKCS#7 Data demo [create]:\n");
      obj = createPKCS7Data(message);
      // transmit data
      System.out.println("\nCMS Data demo [parse]:\n");

      received_message = getData(obj);
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));

   	} catch (Exception ex) {
   	  ex.printStackTrace();
   	  throw new RuntimeException(ex.toString());
   	}
  }

  /**
   * Starts the CMS - PKCS#7 tests.
   */
  public static void main(String argv[]) throws Exception {

   	(new PKCS7CMSDataDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
