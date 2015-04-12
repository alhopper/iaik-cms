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
// $Header: /IAIK-CMS/current/src/demo/DemoSMimeUtil.java 6     11.07.12 10:50 Dbratko $
// $Revision: 6 $
//

package demo;

import java.util.Properties;

import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;
import javax.mail.Session;


/**
 * Some basic utility methods used by the S/MIME demos.
 * 
 * @author Dieter Bratko
 */
public class DemoSMimeUtil extends DemoUtil {
  
  /**
   * Mail session.
   */
  private static Session session_;
  
  /**
   * Default constructor.
   */
  DemoSMimeUtil() {
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
    
    /*
     * Before installing the IAIK provider load classes from activation.jar and mail.jar 
     * to avoid problems due to a bug in the jar file verification mechanism of
     * some JDKs (some version of activation.jar and mail.jar may be signed which
     * may cause a CastException during jar file verification by some buggy JDKs).
     */
    registerMailCapEntries();
    
    // create Session object
  	session_ = getSession();
    
    initRandom(quickStart);
    addIaikProvider();
  }
  
  /**
   * Registers the IAIK content handlers for the mailcap command map.
   */
  public static void registerMailCapEntries() {
    MailcapCommandMap mc = (MailcapCommandMap)CommandMap.getDefaultCommandMap();
    mc.addMailcap("multipart/signed;; x-java-content-handler=iaik.smime.signed_content");
    mc.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=iaik.smime.signed_content");
    mc.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=iaik.smime.encrypted_content");
    mc.addMailcap("application/pkcs7-signature;; x-java-content-handler=iaik.smime.signed_content");
    mc.addMailcap("application/pkcs7-mime;; x-java-content-handler=iaik.smime.encrypted_content");
    mc.addMailcap("application/x-pkcs10;; x-java-content-handler=iaik.smime.pkcs10_content");
    mc.addMailcap("application/pkcs10;; x-java-content-handler=iaik.smime.pkcs10_content");
    CommandMap.setDefaultCommandMap(mc);
  }  
  
  /**
   * Adds the IAIK S/MIME content handlers to the given MailcapCommandMap.
   * 
   * @param mc the MailcapCommandMap to which to add the content handlers
   * 
   * @return the MailcapCommandMap to which the content handlers have been added
   */
  public static CommandMap addContentHandlers(MailcapCommandMap mc) {
    mc.addMailcap("multipart/signed;; x-java-content-handler=iaik.smime.signed_content");
    mc.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=iaik.smime.signed_content");
    mc.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=iaik.smime.encrypted_content");
    mc.addMailcap("application/pkcs7-signature;; x-java-content-handler=iaik.smime.signed_content");
    mc.addMailcap("application/pkcs7-mime;; x-java-content-handler=iaik.smime.encrypted_content");
    mc.addMailcap("application/x-pkcs10;; x-java-content-handler=iaik.smime.pkcs10_content");
    mc.addMailcap("application/pkcs10;; x-java-content-handler=iaik.smime.pkcs10_content");
    return mc;
  }
  
  
  /**
   * Returns (the default) mail session object.
   *
   * @return (the default) session object.
   */
  public static Session getSession() {
    if (session_ == null) {
      // create some properties and get the default Session
      Properties props = new Properties();
      props.put("mail.smtp.host", "mailhost");
      //props.put("mail.debug", "true");
      session_ = Session.getDefaultInstance(props, null);
    }
    return session_; 
  }  
  
  /**
   * Returns a mail session object for the given mailhost.
   * 
   * @param mailhost the mailhost to be used
   *
   * @return a mail session object for the given mailhost.
   */
  public static Session getSession(String mailhost) {
    // create some properties and get the default Session
    Properties props = new Properties();
    props.put("mail.smtp.host", mailhost);
    //props.put("mail.debug", "true");
    Session session = Session.getInstance(props, null);
    return session; 
  }  
  
 
  
}
