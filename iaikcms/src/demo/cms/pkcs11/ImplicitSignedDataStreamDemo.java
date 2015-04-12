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
// $Header: /IAIK-CMS/current/src/demo/cms/pkcs11/ImplicitSignedDataStreamDemo.java 13    23.08.13 14:27 Dbratko $
// $Revision: 13 $
//

package demo.cms.pkcs11;

// class and interface imports
import demo.DemoUtil;


/**
 * This class shows how to sign data (implicit, the content data is included) 
 * according to CMS using the IAIK PKCS#11 provider for accessing the private key
 * on a smart card. This implementation uses the <code>SecurityProvider</code> 
 * feature of the IAIK-CMS toolkit.
 * <p>
 * For running this demo the following packages  are required (in addition to 
 * <code>iaik_cms.jar</code> and <code>iaik_cms_demo.jar</code>):
 * <ul>
 *    <li>
 *       <code>iaik_jce(full).jar</code> (IAIK-JCE crypto toolkit)
 *    </li>   
 *    <li>
 *       <code>iaikPkcs11Wrapper.jar</code> (IAIK PKCS#11 Wrapper)
 *    </li>
 *    <li>
 *       <code>iaikPkcs11Provider.jar</code> (IAIK PKCS#11 Provider)
 *    </li>
 *    <li>
 *       The shared PKCS#11 library (<code>pkcs11wrapper.dll</code> for Windows
 *       and <code>libpkcs11wrapper.so</code> for Unix)
 *     </li>  
 * </ul>
 * <code>iaik_cms.jar</code>, <code>iaik_cms_demo.jar</code>, <code>iaik_jce(full).jar</code>,
 * <code>iaikPkcs11Wrapper.jar</code> and <code>iaikPkcs11Provider.jar</code> have to
 * be put into the classpath, the shared library (<code>pkcs11wrapper.dll</code> or
 * <code>libpkcs11wrapper.so</code>) has to be in your system library search path
 * or in your VM library path, e.g. (on Windows, assuming that all jar files in a lib
 * sub-directory and the dll is in a lib/win32 sub-directory, and the module to be
 * used is \"aetpkss1.dll\" (for G&D StarCos and Rainbow iKey 3000)):
 * <pre>
 * java -Djava.library.path=lib/win32 
 *      -cp lib/iaik_jce.jar;lib/iaikPkcs11Wrapper.jar;lib/iaikPkcs11Provider.jar;lib/iaik_cms.jar;lib/iaik_cms_demo.jar
 *      demo.pkcs11.ImplicitSignedDataStreamDemo aetpkss1.dll
 * </pre>
 * You must use JDK 1.2 or later for running this demo.
 * 
 * @author Dieter Bratko 
 */
public class ImplicitSignedDataStreamDemo extends SignedDataStreamDemo {
  
  /**
   * Creates a ImplicitSignedDataStreamDemo object for the given module name.
   * 
   * @param moduleName the name of the module
   * @param userPin the user-pin (password) for the TokenKeyStore
   *                (may be <code>null</code> to pou-up a dialog asking for the pin)
   */
  public ImplicitSignedDataStreamDemo(String moduleName, char[] userPin) {
    // install provider in super class    
    super(moduleName, userPin);
    System.out.println();
    System.out.println("******************************************************************************Ü*************************");
    System.out.println("*                               PKCS#11  ImplicitSignedDataStreamDemo                                  *");
    System.out.println("* (shows the usage of the CMS SignedData type implementation (implicit) with the IAIK-PKCS11 provider) *");
    System.out.println("********************************************************************************************************");
    System.out.println();
  }

  /**
   * Starts the demo.
   */
  public void start() {
    try {
      byte[] testMessage = "This is the test message to be signed!".getBytes("ASCII");
      getKeyStore();
      getSignatureKey();
      // sign in implicit mode (content data is included)
      byte[] signedData = sign(testMessage, true);
      // verify
      byte[] content = verify(signedData, null);
      System.out.println("##########");
      // we know that we had a text content, thus we can convert into a String
      System.out.println("Content: " + new String(content, "ASCII"));
      System.out.println("##########");
    } catch (Throwable ex) {
      ex.printStackTrace();
      throw new RuntimeException(ex.toString());
    }
  }
  
  /**
   * This is the main method that is called by the JVM during startup.
   *
   * @param args These are the command line arguments.
   */
  public static void main(String[] args) {

    if (args.length == 0) {
      System.out.println("Missing pkcs11 module name.\n");
      printUsage();
    }
    
    String moduleName = args[0];
    char[] userPin = (args.length == 2) ? args[1].toCharArray() : null;
    
    if (args.length > 2) {
      System.out.println("Too many arguments.\n");
      printUsage();
    }
    
    DemoUtil.initDemos();
    
    (new ImplicitSignedDataStreamDemo(moduleName, userPin)).start();;
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
  
  /**
   * Print usage information.
   */
  private final static void printUsage() {
    System.out.println("Usage:\n");
    System.out.println("java ImplicitSignedDataStreamDemo <pkcs11 module name>\n");
    System.out.println("e.g.:");
    System.out.println("java ImplicitSignedDataStreamDemo aetpkss1.dll");
    System.out.println("java ImplicitSignedDataStreamDemo aetpkss1.so");
    DemoUtil.waitKey();
    System.exit(0);
  }


}