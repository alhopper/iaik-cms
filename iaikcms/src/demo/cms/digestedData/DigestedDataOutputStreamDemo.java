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
// $Header: /IAIK-CMS/current/src/demo/cms/digestedData/DigestedDataOutputStreamDemo.java 13    23.08.13 14:20 Dbratko $
// $Revision: 13 $
//

package demo.cms.digestedData;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.cms.CMSException;
import iaik.cms.ContentInfoOutputStream;
import iaik.cms.DigestedDataOutputStream;
import iaik.cms.DigestedDataStream;
import iaik.utils.Util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import demo.DemoUtil;

/**
 * Demonstrates the usage of class {@link iaik.cms.DigestedDataOutputStream} and
 * {@link iaik.cms.DigestedData} for digesting data using the CMS type
 * DigestedData.
 * 
 * @author Dieter Bratko 
 */
public class DigestedDataOutputStreamDemo {

  /**
   * Default constructor.
   */
  public DigestedDataOutputStreamDemo() throws IOException {
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                  DigestedDataOutputStream demo                                 *");
    System.out.println("*        (shows the usage of the DigestedDataOutputStream implementation)        *");
    System.out.println("**********************************************************************************");
    System.out.println();
  }


  /**
   * Uses the IAIK-CMS DigestedDataOutputStream class to create a CMS <code>DigestedData</code> 
   * object for digesting the given message.
   * 
   * @param message the message to be digested, as byte representation
   * @param mode IMPLICIT (include message) or EXPLICIT (do not include message)
   * 
   * @return the BER encoding of the <code>DigestedData</code> object just created,
   *         wrapped in a ContentInfo
   * 
   * @exception CMSException if the <code>DigestedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createDigestedData(byte[] message, int mode) throws CMSException, IOException  {

    System.out.println("Create a new message to be digested:");

    // the stream from which to read the data to be digested
    ByteArrayInputStream is = new ByteArrayInputStream(message);

    // the stream to which to write the DigestedData
    ByteArrayOutputStream resultStream = new ByteArrayOutputStream();
    
    // wrap DigestedData into a ContentInfo 
    ContentInfoOutputStream contentInfoStream = 
      new ContentInfoOutputStream(ObjectID.cms_digestedData, resultStream);
    // create a new DigestedData object 
    DigestedDataOutputStream digestedData = 
      new DigestedDataOutputStream(contentInfoStream,
                                   (AlgorithmID)AlgorithmID.sha256.clone(),
                                   mode);


    int blockSize = 8; // in real world we would use a block size like 2048
    //  write in the data to be digested
    byte[] buffer = new byte[blockSize];
    int bytesRead;
    while ((bytesRead = is.read(buffer)) != -1) {
      digestedData.write(buffer, 0, bytesRead);
    }
    
    // closing the stream finishes digest calculation and closes the underlying stream
    digestedData.close();
    return resultStream.toByteArray();
  }

  /**
   * Parses a CMS <code>DigestedData</code> object and verifies the hash.
   *
   * @param digestedData <code>DigestedData</code> object as BER encoded byte array
   * @param message the message which may have been transmitted out-of-band
   *
   * @return the inherent message as byte array
   * 
   * @exception CMSException if some parsing error occurs or the hash verification fails
   * @exception IOException if an I/O error occurs
   */
  public byte[] getDigestedData(byte[] digestedData, byte[] message) throws CMSException, IOException {

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(digestedData);
    // create the DigestedData object
    DigestedDataStream digested_data = new DigestedDataStream(is);
    
    if (message != null) {
      // explicit mode: set content received by other means
      digested_data.setInputStream(new ByteArrayInputStream(message));
    }

    // get an InputStream for reading the content
    InputStream data = digested_data.getInputStream();
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    Util.copyStream(data, os, null);


    if (digested_data.verify()) {
       System.out.println("Hash ok!");
    } else {
       throw new CMSException("Hash verification failed!");
    }

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
      
      //
      // test CMS Implicit DigestedDataOutputStream
      //
      System.out.println("\nImplicit DigestedDataOutputStream demo [create]:\n");
      encoding = createDigestedData(message, DigestedDataOutputStream.IMPLICIT);
      // transmit data
      System.out.println("\nImplicit DigestedDataOutputStream demo [parse]:\n");
      received_message = getDigestedData(encoding, null);
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));

      //
      // test CMS Explicit DigestedDataOutputStream
      //
      System.out.println("\nExplicit DigestedDataOutputStream demo [create]:\n");
      encoding = createDigestedData(message, DigestedDataOutputStream.EXPLICIT);
      // transmit data
      System.out.println("\nExplicit DigestedDataOutputStream demo [parse]:\n");
      received_message = getDigestedData(encoding, message);
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

    (new DigestedDataOutputStreamDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
