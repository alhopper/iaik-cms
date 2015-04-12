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
// $Header: /IAIK-CMS/current/src/demo/smime/DumpMessage.java 17    6.08.13 17:04 Dbratko $
// $Revision: 17 $
//

package demo.smime;

import iaik.asn1.CodingException;
import iaik.asn1.structures.Attribute;
import iaik.asn1.structures.AttributeValue;
import iaik.cms.SignerInfo;
import iaik.pkcs.pkcs10.CertificateRequest;
import iaik.smime.CompressedContent;
import iaik.smime.EncryptedContent;
import iaik.smime.PKCS10Content;
import iaik.smime.SignedContent;
import iaik.smime.ess.Receipt;
import iaik.smime.ess.ReceiptContent;
import iaik.x509.X509Certificate;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.Date;

import javax.mail.Address;
import javax.mail.Flags;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Part;


/**
 * Simple utility for dumping a message to System.out.
 * The parts of the message are recursively dumped.
 * Note that this utility is not thread-safe (i.e. only
 * one {@link #privateKey private key} can be statically
 * set to decrypt an encrypted content part.
 * 
 * @author Dieter Bratko
 */
public class DumpMessage {
  
  /**
   * Private key to be set for decrypting an encrypted entity.
   */
  public static PrivateKey privateKey;
  
  /**
   * Default constructor.
   */
  public DumpMessage() {
  }

  /**
   * Dumps the given object (message, part,...) to System.out.
   *
   * @param o the object to be dumped
   *
   * @exception if an error occurs
   */
  public static void dump(Object o) throws Exception {

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
      System.out.println("Encryption algorithm: " + ec.getEncryptionAlgorithm().getName());
      ec.decryptSymmetricKey(privateKey, 0);
      dump(ec.getContent());
	} else if (o instanceof SignedContent) {
      // signeded
	    System.out.println("This message is signed!");

      SignedContent sc = (SignedContent)o;

      if (sc.getSMimeType().equals("certs-only")) {
  	    System.out.println("This message contains only certificates!");
        Certificate[] certs = sc.getCertificates();
        for (int i = 0; i < certs.length; ++i) {
          System.out.println(certs[i].toString());
        }
      } else {
        X509Certificate signer = null;
        try {
          signer = sc.verify();
	      System.out.println("This message is signed from: "+signer.getSubjectDN());
	    } catch (SignatureException ex) {
	      throw new SignatureException("Signature verification error: " + ex.toString());
        }

        SignerInfo[] signerInfos = sc.getSignerInfos();
        for (int i=0; i<signerInfos.length; i++) {
           System.out.println("Digest algorithm: " + signerInfos[i].getDigestAlgorithm().getName());
           System.out.println("Signature algorithm: " + signerInfos[i].getSignatureAlgorithm().getName());
           Attribute[] signedAttributes = signerInfos[i].getSignedAttributes();
           if (signedAttributes != null) {
             System.out.println("SignerInfo " + i + " contains the following signed attributes:");
             for (int j = 0; j < signedAttributes.length; j++) {
               dumpAttribute(signedAttributes[j]);
             } 
           }
           Attribute[] unsignedAttributes = signerInfos[i].getUnsignedAttributes();
           if (unsignedAttributes != null) {
            System.out.println("SignerInfo " + i + " contains the following unsigned attributes:");
            for (int j = 0; j < unsignedAttributes.length; j++) {
              dumpAttribute(signedAttributes[j]);
            } 
           } 
        }
        if (!signerInfos[0].isSignerCertificate(signer)) {
          System.out.println("Signer certificate check failed!");
        }
        dump(sc.getContent());
      }
    } else if (o instanceof PKCS10Content) {
      System.out.println("This message contains a certificate request:");
      PKCS10Content pkcs10 = (PKCS10Content)o;
      CertificateRequest request = pkcs10.getCertRequest();
      System.out.println(request.toString());
      try {
         if (request.verify()) {
           System.out.println("Request verification ok for " + request.getSubject());
         } else {
           throw new SignatureException("Incorrect signature!");
         }  
      } catch (SignatureException ex) {
         throw new SignatureException("Request verification error for " + request.getSubject() + ex.getMessage());
      }
    } else if (o instanceof CompressedContent) {
      System.out.println("The content of this message is compressed.");
      CompressedContent compressed = (CompressedContent)o;
      dump(compressed.getContent());  
    } else if (o instanceof ReceiptContent) {
      System.out.println("This message contains a signed receipt:");
      ReceiptContent rc = (ReceiptContent)o;
      Receipt receipt = (Receipt)rc.getContent();
	  System.out.println(receipt);
      // verify the signature (we assume only one signer)
      X509Certificate receiptSigner = null;
      try {
        receiptSigner = rc.verify();
	    System.out.println("This receipt content is signed from: "+receiptSigner.getSubjectDN());
	  } catch (SignatureException ex) {
	    System.err.println("Signature verification error!");
	    throw ex;
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
   * Dumps the given attribute to System.out.
   * 
   * @param attribute the Attribute
   * 
   * @throws CodingException if the attribute cannot be parsed
   */
  private static void dumpAttribute(Attribute attribute) throws CodingException {
    System.out.println(attribute.toString() + "\n");
  }
}
 