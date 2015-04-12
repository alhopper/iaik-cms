// Copyright (C) 2002 IAIK
// http://jce.iaik.at
//
// Copyright (C) 2003 Stiftung Secure Information and 
//                    Communication Technologies SIC
// http://www.sic.st
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
// $Header: /IAIK-CMS/current/src/demo/smime/basic/SMimeShowDemo.java 23    23.08.13 14:30 Dbratko $
// $Revision: 23 $
//

package demo.smime.basic;

import iaik.asn1.structures.Attribute;
import iaik.cms.SignerInfo;
import iaik.pkcs.pkcs10.CertificateRequest;
import iaik.smime.EncryptedContent;
import iaik.smime.PKCS10Content;
import iaik.smime.SignedContent;
import iaik.smime.TrustVerifier;
import iaik.x509.X509Certificate;

import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;

import javax.mail.Address;
import javax.mail.FetchProfile;
import javax.mail.Flags;
import javax.mail.Folder;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Part;
import javax.mail.Session;
import javax.mail.Store;
import javax.mail.URLName;

import demo.DemoSMimeUtil;
import demo.DemoUtil;
import demo.keystore.CMSKeyStore;

/**
 * This class demonstrates the usage of the IAIK S/MIME implementation for downloading
 * and verifying/decrypting signed and/or encrypted emails from some mail server.
 * To run this demo the following packages are required:
 * <ul>
 *    <li>
 *       <code>mail.jar</code>: Get it from <a href="http://www.oracle.com/technetwork/java/javamail/index.html">JavaMail</a>.
 *    </li>   
 *    <li>
 *       <code>activation.jar</code> (required for JDK versions < 1.6): Get it from <a href="http://www.oracle.com/technetwork/java/javase/downloads/index-135046.html">Java Activation Framework</a>.
 *    </li> 
 * </ul>
 *
 * <b>Usage:</b>
 * <pre>
 * SMimeShow [-L url] [-T protocol] [-H host] [-U user] [-P password] [-f mailbox] [msgnum] [-v]
 * </pre>
 * <b>Example</b> to display message 2:
 * <pre>
 * SMimeShow -T imap -H mailhost -U test -P test -f INBOX 2
 * </pre>
 *
 * @see iaik.smime.EncryptedContent
 * @see iaik.smime.SignedContent
 */
public class SMimeShowDemo {

  String from;
  String protocol;
  String host = null;
  String user = null;
  String password = null;
  String mbox = "INBOX";
  String url = null;
  boolean verbose = false;
  PrivateKey privateKey = null;
  TrustVerifier trustVerifier = null;
  
  /**
   * Default constructor. Reads certificates and keys from the demo keystore.
   */
  public SMimeShowDemo() {
    
    System.out.println();
    System.out.println("******************************************************************************************");
    System.out.println("*                                 SMimeShow demo                                         *");
    System.out.println("*     (shows how to parse and verify/decrypt signed and/or encrypted S/MIME messages)    *");
    System.out.println("******************************************************************************************");
    System.out.println();

    // get the private key for decrypting the messages from the KeyStore
    privateKey = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_);
    // the signer certs
    X509Certificate[] certificates = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    
    trustVerifier = new TrustVerifier();
    // add issuer cert of signer to pool of trusted certificates
    trustVerifier.addTrustedCertificate(certificates[1]);
  }
  
  /**
   * Connects to the mail server, downloads messages, verifies/decrypts
   * them (if they are signed/encrypted).
   *
   * @param argv optional parameters like mailhost, account name,...
   *
   * @exception IOException if an I/O related error occurs
   */
  public void show(String[] argv) throws IOException {
    
  	int msgnum = -1;
  	int optind = 0;
    
    // some defaults
    protocol = "pop3";
    host = "mailhost";
    verbose = true;

    if (argv.length > 0) {
  	  for (optind = 0; optind < argv.length; optind++) {
	      if (argv[optind].equals("-T")) {
    		  protocol = argv[++optind];
	      } else if (argv[optind].equals("-H")) {
		      host = argv[++optind];
	      } else if (argv[optind].equals("-U")) {
    		  user = argv[++optind];
	      } else if (argv[optind].equals("-P")) {
		      password = argv[++optind];
	      } else if (argv[optind].equals("-v")) {
    		  verbose = true;
	      } else if (argv[optind].equals("-f")) {
		      mbox = argv[++optind];
	      } else if (argv[optind].equals("-L")) {
    		  url = argv[++optind];
	      } else if (argv[optind].equals("--")) {
    		  optind++;
    		  break;
	      } else if (argv[optind].startsWith("-")) {
    		  System.out.println("Usage: SMimeShow [-L url] [-T protocol] [-H host] [-U user] [-P password] [-f mailbox] [msgnum] [-v]");
		      System.exit(1);
	      } else {
    		  break;
	      }
	    }
    } 

    try {
	    if (optind < argv.length)
         msgnum = Integer.parseInt(argv[optind]);

	    // get the default Session
  	    Session session = DemoSMimeUtil.getSession();

	    // Get a Store object
	    Store store = null;
	    if (url != null) {
    		URLName urln = new URLName(url);
    		store = session.getStore(urln);
    		store.connect();
	    } else {
    	  if (protocol != null) {
  		    store = session.getStore(protocol);
  	  	  } else {
	  	    store = session.getStore();
          }
    	  // Connect
    	  if (host != null || user != null || password != null) {
  		    store.connect(host, user, password);
    	  }	else {
  		    store.connect();
  		  }  
	    }

	    // Open the Folder
	    Folder folder = store.getDefaultFolder();
	    if (folder == null) {
        System.out.println("No default folder");
        System.exit(1);
	    }

	    folder = folder.getFolder(mbox);
	    if (folder == null) {
        System.out.println("Invalid folder");
        System.exit(1);
	    }

//	    folder.open(Folder.READ_WRITE);
	    folder.open(Folder.READ_ONLY);            // only READ for POP3
	    int totalMessages = folder.getMessageCount();

	    if (totalMessages == 0) {
    		System.out.println("Empty folder");
    		folder.close(false);
    		store.close();
    		System.exit(1);
	    }

	    if (verbose) {
    		int newMessages = folder.getNewMessageCount();
    		System.out.println("Total messages = " + totalMessages);
    		System.out.println("New messages = " + newMessages);
    		System.out.println("-------------------------------");
	    }

	    if (msgnum == -1) {
    		// Attributes & Flags for all messages ..
    		Message[] msgs = folder.getMessages();

    		// Use a suitable FetchProfile
    		FetchProfile fp = new FetchProfile();
    		fp.add(FetchProfile.Item.ENVELOPE);
    		fp.add(FetchProfile.Item.FLAGS);
    		fp.add("X-Mailer");
    		folder.fetch(msgs, fp);

    		for (int i = 0; i < msgs.length; i++) {

  		    System.out.println("--------------------------");
  		    System.out.println("MESSAGE #" + (i + 1) + ":");
  		    from = msgs[i].getFrom()[0].toString();
 		    dump(msgs[i]);
    	  }
	    } else {
    	  System.out.println("Getting message number: " + msgnum);
    	  Message m = folder.getMessage(msgnum);
          from = m.getFrom()[0].toString();
    	  dump(m);
	    }

	    folder.close(false);
	    store.close();

	  // System.in.read();
  	} catch (Exception ex) {
	    ex.printStackTrace();
	    throw new RuntimeException(ex.toString());
  	}

  }
  
  /**
   * Dumps the given object (message).
   *
   * @param o the object (message) to be dumped
   *
   * @exception Exception if some error occurs
   */
  public void dump(Object o) throws Exception {

  	if (o instanceof Message) {
	    dumpEnvelope((Message)o);
    }
  	if (o instanceof Part) {
      System.out.println("CONTENT-TYPE: "+((Part)o).getContentType());
  	  o = ((Part)o).getContent();
  	}
	if (o instanceof EncryptedContent) {
      // encrypted
      System.out.println("This message is encrypted!");
      EncryptedContent ec = (EncryptedContent)o;
      ec.decryptSymmetricKey(privateKey, 0);
      dump(ec.getContent());
	} else if (o instanceof SignedContent) {
      // signed
	  System.out.println("This message is signed!");
      SignedContent sc = (SignedContent)o;

      if (sc.getSMimeType().equals("certs-only")) {
        // message only transfers certificates
  	    System.out.println("This message contains only certificates!");
        Certificate[] certs = sc.getCertificates();
        for (int i = 0; i < certs.length; ++i) {
          System.out.println(certs[i].toString());
        }
      } else {
        // message is signed
        X509Certificate signer = null;
        try {
            signer = sc.verify();
	        System.out.println("This message is signed from: "+signer.getSubjectDN());
	   
	        X509Certificate[] certs = iaik.utils.Util.convertCertificateChain(sc.getCertificates());
           // arrange chain to get user cert at index 0
	        certs = iaik.utils.Util.arrangeCertificateChain(certs,false);
	        if (certs != null) {
	          // verify certs and search for trusted cert in chain
            try {
              trustVerifier.verifyCertificateChain(certs);
              System.out.println("Certificate chain trusted!");
            } catch (CertificateException ex) {
	            System.out.println("Certificate chain not trusted!");
            }	           
	        } // else: there may be more certs in the cert set: do some more sophisticated verification
	    } catch (SignatureException ex) {
	        throw new SignatureException("Signature verification error!" + ex.getMessage());
        }

        // is email in cert equal to email from From: header?
        // the email has to be formatted as an "addr-spec" as defined in RFC 822.
        // An addr-spec has the form "local-part@domain".
        if (trustVerifier.checkEMail(from, signer)) {
           System.out.println("EMail is ok!");
        } else {
           System.out.println("EMail not ok!");
        }

        SignerInfo[] signer_infos = sc.getSignerInfos();
        for (int i=0; i<signer_infos.length; i++) {
           Attribute[] signedAttributes = signer_infos[i].getSignedAttributes();
           if (signedAttributes != null) {
             System.out.println("SignerInfo " + i + " contains the following signed attributes:");
             for (int j = 0; j < signedAttributes.length; j++) {
               System.out.println(signedAttributes[j].getType().getName());
               System.out.println(signedAttributes[j]);
               System.out.println();
             } 
           }
           Attribute[] unsignedAttributes = signer_infos[i].getUnsignedAttributes();
           if (unsignedAttributes != null) {
            System.out.println("SignerInfo " + i + " contains the following unsigned attributes:");
            for (int j = 0; j < unsignedAttributes.length; j++) {
              System.out.println(unsignedAttributes[j].getType().getName());
            } 
           } 
        }

        dump(sc.getContent());
      }
    } else if (o instanceof PKCS10Content) {
      System.out.println("This message contains a certificate request:");
      PKCS10Content pkcs10 = (PKCS10Content)o;
      CertificateRequest request = pkcs10.getCertRequest();
      System.out.println(request.toString());
      try {
         if (request.verify())
           System.out.println("Request verification ok for " + request.getSubject());
         else
           System.out.println("Request verification error for " + request.getSubject());
      } catch (SignatureException ex) {
         throw new SignatureException("Request verification error for " + request.getSubject());
      }
    } else if (o instanceof String) {
	  System.out.println("Content is a String");
	  System.out.println("---------------------------");
	  System.out.println((String)o);
	} else if (o instanceof Multipart) {
	  System.out.println("----------------> Content is a Multipart");
	  Multipart mp = (Multipart)o;
	  int count = mp.getCount();
	  for (int i = 0; i < count; i++) {
  	    System.out.println("----------------> Multipart: "+(i+1));
        dump(mp.getBodyPart(i));
      }
	  System.out.println("----------------> End of Multipart");
  	} else if (o instanceof Message) {
	  System.out.println("Content is a Nested Message");
	  System.out.println("---------------------------");
	  dump(o);
	} else if (o instanceof InputStream) {
	  System.out.println("Content is just an input stream: "+o);
	  System.out.println("---------------------------");
	  InputStream is = (InputStream)o;
	  int a;
	  int sum = 0;
	  byte[] buf = new byte[1024];
	  while ((a = is.read(buf)) > 0) {
        sum += a;
      }
	  System.out.println("Length of data: "+sum+" bytes");
  	}
  }
  
  /**
   * Prints the envelope of a message.
   */
  public static void dumpEnvelope(Message m) throws MessagingException {
  	System.out.println("This is the message envelope");
  	System.out.println("---------------------------");
  	Address[] a;
	  // FROM
  	if ((a = m.getFrom()) != null) {
	    for (int j = 0; j < a.length; j++)
	  	System.out.println("FROM: " + a[j].toString());
  	}

    // TO
    if ((a = m.getRecipients(Message.RecipientType.TO)) != null) {
	    for (int j = 0; j < a.length; j++)
    		System.out.println("TO: " + a[j].toString());
  	}

  	// SUBJECT
  	System.out.println("SUBJECT: " + m.getSubject());

  	// DATE
  	Date d = m.getSentDate();
  	System.out.println("SendDate: "+(d != null ? d.toString() : "UNKNOWN"));

    // SIZE
    System.out.println("Size: " + m.getSize());

  	// FLAGS:
  	Flags flags = m.getFlags();
  	StringBuffer sb = new StringBuffer();
  	Flags.Flag[] sf = flags.getSystemFlags(); // get the system flags

  	boolean first = true;
	  for (int i = 0; i < sf.length; i++) {
	    String s;
	    Flags.Flag f = sf[i];
	    if (f == Flags.Flag.ANSWERED)
    		s = "\\Answered";
	    else if (f == Flags.Flag.DELETED)
		    s = "\\Deleted";
	    else if (f == Flags.Flag.DRAFT)
    		s = "\\Draft";
	    else if (f == Flags.Flag.FLAGGED)
		    s = "\\Flagged";
	    else if (f == Flags.Flag.RECENT)
    		s = "\\Recent";
	    else if (f == Flags.Flag.SEEN)
		    s = "\\Seen";
	    else
    		continue;	// skip it
	    if (first)
    		first = false;
	    else
		    sb.append(' ');
	    sb.append(s);
  	}

  	String[] uf = flags.getUserFlags(); // get the user flag strings
  	for (int i = 0; i < uf.length; i++) {
	    if (first)
    		first = false;
	    else
		    sb.append(' ');
	    sb.append(uf[i]);
  	}
	  System.out.println("FLAGS = " + sb.toString());

  	// X-MAILER
  	String[] hdrs = m.getHeader("X-Mailer");
  	if (hdrs != null)
	    System.out.println("X-Mailer: " + hdrs[0]);
  	else
	    System.out.println("X-Mailer NOT available");
  }
  
  /** 
   * Main method.
   */
  public static void main(String argv[]) throws IOException {
    DemoSMimeUtil.initDemos();
    (new SMimeShowDemo()).show(argv);
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
