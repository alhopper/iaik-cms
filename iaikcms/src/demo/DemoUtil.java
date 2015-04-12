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
// $Header: /IAIK-CMS/current/src/demo/DemoUtil.java 24    29.11.13 16:30 Dbratko $
// $Revision: 24 $
//

package demo;

import iaik.asn1.ObjectID;
import iaik.security.provider.IAIK;
import iaik.security.random.MetaSeedGenerator;
import iaik.security.random.SecRandom;
import iaik.security.random.SeedGenerator;

import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.util.Random;

/**
 * Some basic utility methods used by the demos.
 * 
 * @author Dieter Bratko
 */
public class DemoUtil {
  
  /** Debug flag for all demos */
  public final static boolean DEMO_DEBUG = true;
  
  /**
   * Base OID for IAIK-CMS demos.
   */
  public final static ObjectID IAIK_JAVA_SECURITY_DEMO_CMS_OID = new ObjectID("1.3.6.1.4.1.2706.2.2.4", "IAIK JavaSecurity CMS Demo");
  
  /**
   * Greeting message.
   */
  final static String[] GREETING = {
    "*                                                                            *",
    "*         Welcome to the IAIK-CMS/SMIMEv3 Demo Programs                      *",
    "*                                                                            *",
    "* These simple programs show how to use the IAIK-CMS library. Please         *", 
    "* see  the  documentation and  the source code  for more information.        *",
    "*                                                                            *",
    "*                                                                            *",
    "* NOTE that most of the demos require certificates to work, they are         *", 
    "* taken from a keystore file (cms.keystore) located  in your current         *",
    "* working directory. If yet not exist, the keystore can be generated         *",
    "* by calling demo.keystore.SetupCMSKeyStore.                                 *",
    "*                                                                            *",
    "",
  };

  /**
   * Initialization done?
   */
  static boolean initialized_ = false;
  
  /**
   * Version number of the IAIK-JCE crypto provider.
   */
  static double iaikProviderVersion_ = -1;
  
  /**
   * Empty constructor.
   */
  DemoUtil() {
    // empty
  }
  
  /** Perform a some initial setup to allow the demos to work */
  public synchronized static void initDemos() {
    initDemos(true);
  }
  
  /**
   *  Perform a some initial setup to allow the demos to work
   *  
   *  @param quickStart whether to init the random generator with a
   *                    (not strong) seed for quick start (ONLY FOR 
   *                    DEMO PURPOSES; NOT FOR PRODUCTION ENVIRONMENT!)
   */
  public synchronized static void initDemos(boolean quickStart) {
    
    if( initialized_ ) {
      return;
    }
    initialized_ = true;
    for( int i=0; i<GREETING.length; i++ ) {
      System.out.println(GREETING[i]);
    }
    initRandom(quickStart);
    addIaikProvider();
  }
  

  /**
   * Adds the IAIK JCE as a first security provider. 
   */
  public static void addIaikProvider() {
    IAIK.addAsProvider();
    Provider iaikProv = Security.getProvider("IAIK");
    iaikProviderVersion_ = iaikProv.getVersion();
  }
  
  /**
   * Gets the version number of the IAIK-JCE provider used for this demos.
   *
   * @return the version number of the IAIK JCA/JCE provider
   */
  public static double getIaikProviderVersion() {
    if (iaikProviderVersion_ == -1) {
      addIaikProvider();   
    }    
    return iaikProviderVersion_; 
  }  
  
  /**
   * Adds the cryptography provider with the given name.
   *
   * Note that it may <em>not</em> be enough to just add it as a provider;
   * see the {@link iaik.cms.SecurityProvider SecurityProvider} class for more information.
   *
   * @param name the name of the provider to be added
   */
  public static void addProvider(String name) {
    try {
      Class clazz = Class.forName(name);
      Provider provider = (Provider)clazz.newInstance();
      Security.addProvider(provider);
    } catch (ClassNotFoundException ex) {
      System.out.println("Provider IAIK not found. Add iaik_jce.jar or iaik_jce_full.jar to your classpath.");
      System.out.println("If you are going to use a different provider please take a look at Readme.html!");
      System.exit(0);
    } catch (Exception ex) {
      System.out.println("Error adding provider:");
      ex.printStackTrace(System.err);
      System.exit(0);
    }
  }
  
  /**
   * Setup the random number generator for a quick start.
   * THIS IS NOT SECURE AND SHOULD BE USED FOR DEMO PURPOSES ONLY.
   * ANY CRYPTOGRAPHIC KEY DERIVED IN THIS WAY IS WEAK AND NO STRONGER THAN 20 BIT!!!
   */
  public static void initRandom() {
    System.out.println("Quick-starting random number generator (not for use in production systems!)...");
    Random random = new Random();
    byte[] seed = new byte[20];
    random.nextBytes(seed);
    MetaSeedGenerator.setSeed(seed);
    SeedGenerator.setDefault(MetaSeedGenerator.class);
  }
  
  /**
   * Setup the random number generator for a quick start.
   * THIS IS NOT SECURE AND SHOULD BE USED FOR DEMO PURPOSES ONLY.
   * ANY CRYPTOGRAPHIC KEY DERIVED IN THIS WAY IS WEAK AND NO STRONGER THAN 20 BIT!!!
   * 
   * @param quick whether to init the random generator with a (not strong) seed 
   *                for quick start (only for demonstration purposes)
   */
  public static void initRandom(boolean quick) {
    if (quick) {
      System.out.println("Quick-starting random number generator (not for use in production systems!)...");
      Random random = new Random();
      byte[] seed = new byte[20];
      random.nextBytes(seed);
      MetaSeedGenerator.setSeed(seed);
      SeedGenerator.setDefault(MetaSeedGenerator.class);
    } else {
      // create a new Thread which initializes the Secure Random Number generator
      (new Thread() {
        public void run() {
          setPriority(Thread.MIN_PRIORITY);
          SecRandom.getDefault().nextInt();
        }
      }).start();
    }
  }
  
  
  /**
   * Wait for the user to press the return key on System.in.
   */
  public static void waitKey() {
    try {
      System.out.println("Hit the <RETURN> key.");
      do {
        System.in.read();
      } while( System.in.available() > 0 );
    } catch( IOException e ) {
      // ignore
    }
  }
  
}
