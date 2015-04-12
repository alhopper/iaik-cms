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
// $Header: /IAIK-CMS/current/src/demo/cms/digestedData/DigestedDataDemo.java 17    23.08.13 14:20 Dbratko $
// $Revision: 17 $
//

package demo.cms.digestedData;

import iaik.asn1.structures.AlgorithmID;
import iaik.cms.CMSException;
import iaik.cms.DigestedData;
import iaik.cms.DigestedDataStream;
import iaik.security.random.SecRandom;
import iaik.utils.Util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import demo.DemoUtil;

/**
 * Demonstrates the usage of class {@link iaik.cms.DigestedDataStream} and
 * {@link iaik.cms.DigestedData} for digesting data using the CMS type
 * DigestedData.
 * 
 * @author Dieter Bratko 
 */
public class DigestedDataDemo {

  // secure random number generator
  SecureRandom random;

  /**
   * Default constructor.
   */
  public DigestedDataDemo() throws IOException {
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                           CMSDigestedData demo                                 *");
    System.out.println("*        (shows the usage of the CMS DigestedData type implementation)           *");
    System.out.println("**********************************************************************************");
    System.out.println();
    
    random = SecRandom.getDefault();
  }


  /**
   * Creates a CMS <code>DigestedData</code> object.
   * <p>
   * @param message the message to be digested, as byte representation
   * @param mode IMPLICIT (include message) or EXPLICIT (do not include message)
   * @return the DER encoding of the <code>DigestedData</code> object just created
   * @exception CMSException if the <code>DigestedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createDigestedDataStream(byte[] message, int mode) throws CMSException, IOException  {

    System.out.println("Create a new message to be digested:");

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);

    // create a new DigestedData object which includes the data
    DigestedDataStream digested_data = null;

    digested_data = new DigestedDataStream(is, (AlgorithmID)AlgorithmID.sha256.clone(), mode);


    // write the data through DigestedData to any out-of-band place
    if (mode == DigestedDataStream.EXPLICIT) {
      InputStream data_is = digested_data.getInputStream();
      byte[] buf = new byte[1024];
      int r;
      while ((r = data_is.read(buf)) > 0)
        ;   // skip data
    }

    // return the DigestedData as DER encoded byte array with block size 2048
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    digested_data.writeTo(os, 2048);
    return os.toByteArray();
  }

  /**
   * Parses a CMS <code>DigestedData</code> object and verifies the hash.
   *
   * @param digestedData <code>DigestedData</code> object as DER encoded byte array
   * @param message the the message which was transmitted out-of-band
   *
   * @return the inherent message as byte array
   * @exception CMSException if some parsing error occurs or the hash verification fails
   * @exception IOException if an I/O error occurs
   */
  public byte[] getDigestedDataStream(byte[] digestedData, byte[] message) throws CMSException, IOException {

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(digestedData);
    // create the DigestedData object
    DigestedDataStream digested_data = null;
    if (message == null) {
      // implicitly; read the DER encoded object
      digested_data = new DigestedDataStream(is);
    } else {
      // explicitly; set the data stream for digesting the message
      digested_data = new DigestedDataStream(new ByteArrayInputStream(message), (AlgorithmID)AlgorithmID.sha256.clone());
    }

    // get an InputStream for reading the content
    InputStream data = digested_data.getInputStream();
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    Util.copyStream(data, os, null);

    if (message != null) {
      // explicit mode: decode the DigestedData now  
      digested_data.decode(is);
    }

    if (digested_data.verify()) {
       System.out.println("Hash ok!");
    } else {
       throw new CMSException("Hash verification failed!");
    }

    return os.toByteArray();
  }


  /**
   * Creates a CMS <code>DigestedData</code> object.
   * <p>
   *
   * @param message the message to be digested, as byte representation
   * @param mode IMPLICIT (include message) or EXPLICIT (do not include message)
   * @return the DER encoded <code>DigestedData</code>
   * @exception CMSException if the <code>DigestedData</code> object cannot
   *                          be created
   * @exception IOException if an I/O error occurs
   */
  public byte[] createDigestedData(byte[] message, int mode) throws CMSException, IOException  {

    System.out.println("Create a new digested message:");

    // create a new DigestedData object which includes the data
    DigestedData digested_data = new DigestedData(message, (AlgorithmID)AlgorithmID.sha256.clone(), mode);

    return digested_data.getEncoded();
  }

  /**
   * Parses a CMS <code>DigestedData</code> object and verifies the hash value.
   *
   * @param encoding the DER encoded <code>DigestedData</code> object 
   * @param message the the message which was transmitted out-of-band (explicit digested)
   *
   * @return the message
   * @exception CMSException if some parsing error occurs or the hash verification fails
   * @exception IOException if an I/O error occurs
   */
  public byte[] getDigestedData(byte[] encoding, byte[] message) throws CMSException, IOException {
    
    ByteArrayInputStream encodedStream = new ByteArrayInputStream(encoding);
    // create the DigestedData object
    DigestedData digested_data = null;
    if (message == null) {
      // implicitly digested; read the ASN.1 object
      digested_data = new DigestedData(encodedStream);
    }
    else {
      // explicitly digested; set the data for digesting the message
      try {
         digested_data = new DigestedData(message, (AlgorithmID)AlgorithmID.sha256.clone());
         // if explicitly digested now the DER encoded object
         digested_data.decode(encodedStream);

      } catch (NoSuchAlgorithmException ex) {
         throw new CMSException(ex.getMessage());
      }
    }

    // now verify the digest
    if (digested_data.verify()) {
       System.out.println("Hash ok!");
    } else {
       throw new CMSException("Hash verification failed!");
    }

    return digested_data.getContent();
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

      // the stream implementation
   
      //
      // test CMS Implicit DigestedDataStream
      //
      System.out.println("\nImplicit DigestedDataStream demo [create]:\n");
      encoding = createDigestedDataStream(message, DigestedDataStream.IMPLICIT);
      // transmit data
      System.out.println("\nImplicit DigestedDataStream demo [parse]:\n");
      received_message = getDigestedDataStream(encoding, null);
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));

      //
      // test CMS Explicit DigestedDataStream
      //
      System.out.println("\nExplicit DigestedDataStream demo [create]:\n");
      encoding = createDigestedDataStream(message, DigestedDataStream.EXPLICIT);
      // transmit data
      System.out.println("\nExplicit DigestedDataStream demo [parse]:\n");
      received_message = getDigestedDataStream(encoding, message);
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));
      
      // the non-stream implementation
      System.out.println("\nNon-stream implementation demos");
      System.out.println("===============================");

      //
      // test CMS Implicit DigestedData
      //
      System.out.println("\nImplicit DigestedData demo [create]:\n");
      encoding = createDigestedData(message, DigestedData.IMPLICIT);
      // transmit data
      System.out.println("\nImplicit DigestedData demo [parse]:\n");
      received_message = getDigestedData(encoding, null);
      System.out.print("\nContent: ");
      System.out.println(new String(received_message));

      //
      // test CMS Explicit DigestedData
      //
      System.out.println("\nExplicit DigestedData demo [create]:\n");
      encoding = createDigestedData(message, DigestedData.EXPLICIT);
      // transmit data
      System.out.println("\nExplicit DigestedData demo [parse]:\n");
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

    (new DigestedDataDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
