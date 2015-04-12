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
// $Header: /IAIK-CMS/current/src/demo/smime/basic/SMimeCamelliaDemo.java 7     23.08.13 14:30 Dbratko $
// $Revision: 7 $
//

package demo.smime.basic;

import iaik.asn1.structures.AlgorithmID;
import iaik.smime.SMimeBodyPart;
import iaik.smime.SMimeMultipart;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.activation.DataHandler;
import javax.activation.FileDataSource;
import javax.mail.Message;
import javax.mail.Multipart;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;

import demo.DemoSMimeUtil;
import demo.DemoUtil;
import demo.smime.DumpMessage;

/**
 * This class demonstrates the usage of the IAIK S/MIME implementation with the Camellia
 * encryption algorithm. It shows how to create encrypted S/MIME messages and how to parse
 * them and decrypt the content.
 * To run this demo the following packages are required:
 * <ul>
 *    <li>
 *       IAIK-JCE (<code>iaik_jce.jar</code>) version &gt;3.18
 *    </li>
 *        <code>mail.jar</code>: Get it from <a href="http://www.oracle.com/technetwork/java/javamail/index.html">JavaMail</a>.
 *    </li>   
 *    <li>
 *        <code>activation.jar</code> (required for JDK versions < 1.6): Get it from <a href="http://www.oracle.com/technetwork/java/javase/downloads/index-135046.html">Java Activation Framework</a>.
 *    </li>
 * </ul>
 * 
 * @author Dieter Bratko
 */
public class SMimeCamelliaDemo extends SMimeDemo {
    
  /**
   * Default constructor. Reads certificates and keys from the demo keystore.
   */
  public SMimeCamelliaDemo() {
    
     super();
  }
  
  /**
   * Starts the demo.
   *
   * @exception IOException if an I/O related error occurs
   */
  public void start() throws IOException {

  	// get the default Session
  	Session session = DemoSMimeUtil.getSession();

  	try {
      // Create a demo Multipart
      MimeBodyPart mbp1 = new SMimeBodyPart();
      mbp1.setText("This is a Test of the IAIK S/MIME implementation!\n\n");
	  // attachment
      MimeBodyPart attachment = new SMimeBodyPart();
      attachment.setDataHandler(new DataHandler(new FileDataSource("test.html")));
      attachment.setFileName("test.html");
        
      Multipart mp = new SMimeMultipart();
      mp.addBodyPart(mbp1);
      mp.addBodyPart(attachment);

      Message msg;    // the message to send
      ByteArrayOutputStream baos = new ByteArrayOutputStream(); // we write to a stream
      ByteArrayInputStream bais;  // we read from a stream

     
      // Create encrypted message using Camellia for content encryption
      
      msg = createEncryptedMessage(session, (AlgorithmID)AlgorithmID.camellia128_CBC.clone(), 128);
      System.out.println("creating encrypted message [Camellia/128]...");
      baos.reset();
      msg.saveChanges();
      msg.writeTo(baos);
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.dump(msg);
      
      System.out.println("\n\n*****************************************\n\n");
      
      msg = createEncryptedMessage(session, (AlgorithmID)AlgorithmID.camellia192_CBC.clone(), 192);
      System.out.println("creating encrypted message [Camellia/192]...");
      baos.reset();
      msg.saveChanges();
      msg.writeTo(baos);
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.dump(msg);
      
      System.out.println("\n\n*****************************************\n\n");

      msg = createEncryptedMessage(session, (AlgorithmID)AlgorithmID.camellia256_CBC.clone(), 256);
      System.out.println("creating encrypted message [Camellia/256]...");
      baos.reset();
      msg.saveChanges();
      msg.writeTo(baos);
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.dump(msg);
      
      System.out.println("\n\n*****************************************\n\n");



  	} catch (Exception ex) {
	    ex.printStackTrace();
	    throw new RuntimeException(ex.toString());
  	}
  }
  

  /**
   * The main method.
   */
  public static void main(String[] argv) throws IOException {

    DemoSMimeUtil.initDemos();
   	(new SMimeCamelliaDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
