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
// $Header: /IAIK-CMS/current/src/demo/smime/big/BigSMimeMailDemo.java 16    23.08.13 14:32 Dbratko $
// $Revision: 16 $
//

package demo.smime.big;

import iaik.asn1.structures.AlgorithmID;
import iaik.cms.CMSAlgorithmID;
import iaik.smime.CompressedContent;
import iaik.smime.EncryptedContent;
import iaik.smime.SMimeParameters;
import iaik.smime.SharedFileInputStream;
import iaik.smime.SignedContent;
import iaik.utils.CryptoUtils;
import iaik.utils.Util;
import iaik.x509.X509Certificate;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;
import java.util.Random;

import javax.activation.DataHandler;
import javax.activation.FileDataSource;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Part;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import demo.DemoSMimeUtil;
import demo.DemoUtil;
import demo.keystore.CMSKeyStore;
import demo.smime.DumpMessage;

/**
 * This class demonstrates the usage of the IAIK S/MIME implementation for
 * handling S/MIME message with big content data.
 * <p>
 * The only difference to the common usage of this S/MIME library is that
 * this demo uses a temporary file directory to which the content of the
 * big messages is written during processing. The temporary directory is
 * created by calling method {@link iaik.smime.SMimeParameters#setTempDirectory(String, int)
 * SMimeParameters#setTempDirectory}:
 * <pre>
 * int bufSize = 16348;
 * String tmpDir = ...;
 * SMimeParameters.setTempDirectory(tmpDir, bufSize);
 * </pre>
 * See Javadoc of {@link iaik.smime.SMimeParameters#setTempDirectory(String, int)
 * SMimeParameters#setTempDirectory} for usage information.
 * <p>
 * To run this demo the following packages are required:
 * <ul>
 * <li>mail.jar: Get it from <a href="http://www.oracle.com/technetwork/java/javamail/index.html">JavaMail</a>.
 * <li>activation.jar: Get it from <a href="http://www.oracle.com/technetwork/java/javase/downloads/index-135046.html">Java Activation Framework</a>.
 * </ul>
 * The data for this demo is randomly created and stored into a file which is
 * deleted again at the end of this demo. Note that running this demo may take 
 * some certain time because it processes some MB of data.
 * 
 * @author Dieter Bratko
 */
public class BigSMimeMailDemo {

    // The directory where to write mails.
  final static String TEST_DIR = "test";
  
  // The name of the data file.
  final static String DATA_FILE_NAME = TEST_DIR + "/test.dat";
  
  // The data size (in bytes).
  final static int DATA_SIZE = 15000 * 1024; 
    

  String firstName_ = "John";                     // name of sender
  String lastName_ = "SMime";
  String from_ = "smimetest@iaik.tugraz.at";      // email sender
  String to_ = "smimetest@iaik.tugraz.at";        // email recipient
  String host_ = "mailhost";                      // name of the mailhost

  X509Certificate[] signerCertificates_;          // list of certificates to include in the S/MIME message
  X509Certificate recipientCertificate_;          // certificate of the recipient
  PrivateKey recipientKey_;                       // the private key of the recipient
  X509Certificate signerCertificate_;             // certificate of the signer/sender
  X509Certificate encryptionCertOfSigner_;        // signer uses different certificate for encryption
  PrivateKey signerPrivateKey_;                   // private key of the signer/sender

  
  /**
   * Default constructor. Reads certificates and keys from the demo keystore.
   */
  public BigSMimeMailDemo() {
    
    System.out.println();
    System.out.println("******************************************************************************************");
    System.out.println("*                                 BigSMimeMailDemo demo                                  *");
    System.out.println("*                  (shows how to create and parse big S/MIME messages)                   *");
    System.out.println("******************************************************************************************");
    System.out.println();
    
    // get the certificates from the KeyStore
    signerCertificates_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    signerPrivateKey_ = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    signerCertificate_ = signerCertificates_[0];

    // recipient = signer for this test
    recipientCertificate_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_)[0];
    recipientKey_ = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_);
    encryptionCertOfSigner_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT)[0];
  }
  
  /**
   * Starts the demo.
   *
   * @exception IOException if an I/O related error occurs
   */
  public void start() throws IOException {
    
    // first we create the big test data file (may take some time
    createDataFile(DATA_FILE_NAME, DATA_SIZE);

  	// get the default Session
  	Session session = DemoSMimeUtil.getSession();
    
    // the name of the file holding the test message
    String fileName;
    // the file holding the test message
    File file;
    // the stream to which to write the mail to a file
    FileOutputStream fos = null;
    // the stream from which to read the mail from a file
    SharedFileInputStream fis = null;
    
    // we specify a temp directory to which temporary message contents
    // shall be written
    int bufSize = 64 * 1024;
    SMimeParameters.setTempDirectory(TEST_DIR, bufSize);
  	
    try {
      
      // DataHandler for reading the data
      DataHandler dataHandler = new DataHandler(new FileDataSource(DATA_FILE_NAME));

      Message msg;    // the message to send
      
      // 1. Explicitly signed message
      System.out.println("Creating explicitly signed message...");
      // create
      msg = createSignedMessage(session, dataHandler, false);
	  msg.saveChanges();
      fileName = TEST_DIR + "/explicitSigned.eml";
      fos = new FileOutputStream(fileName);
      System.out.println("Writing explicitly signed message to " + fileName);
	  msg.writeTo(new BufferedOutputStream(fos));
      fos.close();
      System.out.println("Explicitly signed message created.");
      // read
      file = new File(fileName);
	  fis = new SharedFileInputStream(file);
      System.out.println("Parsing explicitly signed message from " + fileName);
	  msg = new MimeMessage(null, fis);
	  parse(msg);
	  fis.close();
      file.delete();
	  System.out.println("\n\n*****************************************\n\n");


      // 2. Implicitly signed message
      msg = createSignedMessage(session, dataHandler, true);
      System.out.println("creating implicitly signed message...");
      fileName = TEST_DIR + "/implicitSigned.eml";
      fos = new FileOutputStream(fileName);
      System.out.println("Writing implicitly signed message to " + fileName);
      msg.writeTo(new BufferedOutputStream(fos));
      fos.close();
      System.out.println("Implicitly signed message created.");
      // read
      file = new File(fileName);
      fis = new SharedFileInputStream(file);
      System.out.println("Parsing implicitly signed message from " + fileName);
      msg = new MimeMessage(null, fis);
	  parse(msg);
	  fis.close();
      file.delete();
	  System.out.println("\n\n*****************************************\n\n");

      // 3. Encrypted messages (AES)
      System.out.println("Creating encrypted message [AES/128]...");
      msg = createEncryptedMessage(session, dataHandler, (AlgorithmID)AlgorithmID.aes128_CBC.clone(), 128);
      fileName = TEST_DIR + "/encrypted.eml";
      fos = new FileOutputStream(fileName);
      System.out.println("Writing encrypted message to " + fileName);
      msg.writeTo(new BufferedOutputStream(fos));
      fos.close();
      System.out.println("Encrypted message created.");
      // read
      file = new File(fileName);
      fis = new SharedFileInputStream(file);
      System.out.println("Parsing encrypted message from " + fileName);
      msg = new MimeMessage(null, fis);
      parse(msg);
      fis.close();
      file.delete();
	  
	  System.out.println("\n\n*****************************************\n\n");

      // 4. Implicitly signed and encrypted message
      System.out.println("Creating implicitly signed and encrypted message");
      msg = createSignedAndEncryptedMessage(session, dataHandler, true);
      fileName = TEST_DIR + "/impsigenc.eml";
      fos = new FileOutputStream(fileName);
      System.out.println("Writing implicitly signed and encrypted message to " + fileName);
      msg.writeTo(new BufferedOutputStream(fos));
      fos.close();
      System.out.println("Implicitly signed and encrypted message created.");
      // read
      file = new File(fileName);
      fis = new SharedFileInputStream(file);
      System.out.println("Parsing implicitly signed and encrypted message from " + fileName);
      msg = new MimeMessage(null, fis);
      parse(msg);
      fis.close();
      file.delete();
	  
	  System.out.println("\n\n*****************************************\n\n");

      // 6. Explicitly signed and encrypted message 
      System.out.println("Creating explicitly signed and encrypted message");
      msg = createSignedAndEncryptedMessage(session, dataHandler, false);
      fileName = TEST_DIR + "/impsigenc.eml";
      fos = new FileOutputStream(fileName);
      System.out.println("Writing explicitly signed and encrypted message to " + fileName);
      msg.writeTo(new BufferedOutputStream(fos));
      fos.close();
      System.out.println("Explicitly signed and encrypted message created.");
      // read
      file = new File(fileName);
      fis = new SharedFileInputStream(file);
      System.out.println("Parsing explicitly signed and encrypted message from " + fileName);
      msg = new MimeMessage(null, fis);
      parse(msg);
      fis.close();
      file.delete();
	  
	  System.out.println("\n\n*****************************************\n\n");

	  // 7. compressed message
      System.out.println("Creating compressed message");
	  msg = createCompressedMessage(session, dataHandler, (AlgorithmID)CMSAlgorithmID.zlib_compress.clone());
      fileName = TEST_DIR + "/compressed.eml";
      System.out.println("Writing compressed message to " + fileName);
      fos = new FileOutputStream(fileName);
      msg.writeTo(new BufferedOutputStream(fos));
      fos.close();
      System.out.println("Compressed message created.");
      // read
      file = new File(fileName);
      fis = new SharedFileInputStream(file);
      System.out.println("Parsing compressed message from " + fileName);
      msg = new MimeMessage(null, fis);
      parse(msg);
      fis.close();
      file.delete();


  	} catch (Exception ex) {
      if (fos != null) {
        try {
          fos.close();
        } catch (Exception e) {
          // ignore
        }
      }
      if (fis != null) {
        try {
          fis.close();
        } catch (Exception e) {
          // ignore
        }
      }
      ex.printStackTrace();
      throw new RuntimeException(ex.toString());

    } finally {
      // try to delete temporary directory
      SMimeParameters.deleteTempDirectory();
      SMimeParameters.setTempDirectory(null, -1);
      // delete data file
      File dataFile = new File(DATA_FILE_NAME);
      dataFile.delete();
    }

  }
  
  
  /**
   * Creates a MIME message container with the given subject for the given session.
   * 
   * @param session the mail sesion
   * @param subject the subject of the message
   *
   * @return the MIME message with FROM, TO, DATE and SUBJECT headers (without content)
   *
   * @exception MessagingException if the message cannot be created
   */
  public Message createMessage(Session session, String subject) throws MessagingException {
    MimeMessage msg = new MimeMessage(session);
    msg.setFrom(new InternetAddress(from_));
	msg.setRecipients(Message.RecipientType.TO,	InternetAddress.parse(to_, false));
	msg.setSentDate(new Date());
    msg.setSubject(subject);
    return msg;
  }
  

  /**
   * Creates a signed and encrypted message.
   *
   * @param session the mail session
   * @param dataHandler the content of the message to be signed and encrypted
   * @param implicit whether to use implicit (application/pkcs7-mime) or explicit
   *                 (multipart/signed) signing
   * 
   * @return the signed and encrypted message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createSignedAndEncryptedMessage(Session session, DataHandler dataHandler, boolean implicit)
    throws MessagingException {

    String subject = null;
    if (implicit) {
      subject = "IAIK-S/MIME: Implicitly Signed and Encrypted";
    } else {
      subject = "IAIK-S/MIME: Explicitly Signed and Encrypted";
    }
    Message msg = createMessage(session, subject);

    SignedContent sc = new SignedContent(implicit);
    sc.setDataHandler(dataHandler);
    sc.setCertificates(signerCertificates_);
    try {
      sc.addSigner((RSAPrivateKey)signerPrivateKey_, signerCertificate_);
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Algorithm not supported: " + ex.getMessage(), ex);
    }

    EncryptedContent ec = new EncryptedContent(sc);
    // encrypt for the recipient
    ec.addRecipient(recipientCertificate_, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // I want to be able to decrypt the message, too
    ec.addRecipient(encryptionCertOfSigner_, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // set the encryption algorithm
    try {
      ec.setEncryptionAlgorithm((AlgorithmID)AlgorithmID.rc2_CBC.clone(), 128);
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Content encryption algorithm not supported: " + ex.getMessage());   
    }   
    msg.setContent(ec, ec.getContentType());
    // let the EncryptedContent update some message headers
    ec.setHeaders(msg);

    return msg;
  }
  
  /**
   * Creates a signed message.
   *
   * @param session the mail session
   * @param dataHandler the content of the message to be signed
   * @param implicit whether to use implicit (application/pkcs7-mime) or explicit
   *                 (multipart/signed) signing
   * 
   * @return the signed message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createSignedMessage(Session session, DataHandler dataHandler, boolean implicit)
      throws MessagingException {

    String subject = null;
    StringBuffer buf = new StringBuffer();
    
    if (implicit) {
      subject = "IAIK-S/MIME: Implicitly Signed";
      buf.append("This message is implicitly signed!\n");
      buf.append("You need an S/MIME aware mail client to view this message.\n");
      buf.append("\n\n");
    } else {
      subject = "IAIK-S/MIME: Explicitly Signed";
      buf.append("This message is explicitly signed!\n");
      buf.append("Every mail client can view this message.\n");
      buf.append("Non S/MIME mail clients will show the signature as attachment.\n");
      buf.append("\n\n");
    }
    
    Message msg = createMessage(session, subject);

    SignedContent sc = new SignedContent(implicit);

    if (dataHandler != null) {
      sc.setDataHandler(dataHandler);
    } else {
      sc.setText(buf.toString());
    }
    sc.setCertificates(signerCertificates_);

    try {
      sc.addSigner((RSAPrivateKey)signerPrivateKey_, signerCertificate_);
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Algorithm not supported: " + ex.getMessage(), ex);
    }

    msg.setContent(sc, sc.getContentType());
    // let the SignedContent update some message headers
    sc.setHeaders(msg);
    return msg;
  }
  
  /**
   * Creates an encrypted message.
   *
   * @param session the mail session
   * @param dataHandler the dataHandler providing the content to be encrypted
   * @param algorithm the content encryption algorithm to be used
   * @param keyLength the length of the secret content encryption key to be created and used
   * 
   * @return the encrypted message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createEncryptedMessage(Session session,
                                        DataHandler dataHandler,
                                        AlgorithmID algorithm,
                                        int keyLength)
      throws MessagingException {

    StringBuffer subject = new StringBuffer();
    subject.append("IAIK-S/MIME: Encrypted ["+algorithm.getName());
    if (keyLength > 0) {
      subject.append("/"+keyLength);
    }  
    subject.append("]");
    Message msg = createMessage(session, subject.toString());

    EncryptedContent ec = new EncryptedContent();

    
    ec.setDataHandler(dataHandler);
    // encrypt for the recipient
    ec.addRecipient(recipientCertificate_, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // I want to be able to decrypt the message, too
    ec.addRecipient(encryptionCertOfSigner_, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    try {
      ec.setEncryptionAlgorithm(algorithm, keyLength);
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Content encryption algorithm not supported: " + ex.getMessage());   
    }   

    msg.setContent(ec, ec.getContentType());
    // let the EncryptedContent update some message headers
    ec.setHeaders(msg);

    return msg;
  }
  
  /**
   * Creates a compressed message.
   *
   * @param session the mail session
   * @param dataHandler the datahandler supplying the content to be compressed
   * @param algorithm the compression algorithm to be used
   * 
   * @return the compressed message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createCompressedMessage(Session session, DataHandler dataHandler, AlgorithmID algorithm)
      throws MessagingException {

    String subject = "IAIK-S/MIME: Compressed ["+algorithm.getName()+"]";
    Message msg = createMessage(session, subject.toString());

    CompressedContent compressedContent = new CompressedContent();
    compressedContent.setDataHandler(dataHandler);   
    
    try {
      compressedContent.setCompressionAlgorithm(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Compression algorithm not supported: " + ex.getMessage());   
    }   

    msg.setContent(compressedContent, compressedContent.getContentType());
    // let the CompressedContent update some message headers
    compressedContent.setHeaders(msg);

    return msg;
  }
  
  /**
   * Parses the given object (message, part, ... ).
   * 
   * @param o the object (message, part, ... ) to be parsed
   * 
   * @exception if an exception occurs while parsing
   */
  public void parse(Object o) throws Exception {
    if (o instanceof Message) {
      DumpMessage.dumpEnvelope((Message)o);
    }
    if (o instanceof Part) {
      System.out.println("CONTENT-TYPE: "+((Part)o).getContentType());
      o = ((Part)o).getContent();
    }

    if (o instanceof EncryptedContent) {
      
      // encrypted
      System.out.println("This message is encrypted!");

      EncryptedContent ec = (EncryptedContent)o;
      ec.decryptSymmetricKey(recipientKey_, recipientCertificate_);
      parse(ec.getContent());
      
    } else if (o instanceof SignedContent) {
      
      // signed
      System.out.println("This message is signed!");

      SignedContent sc = (SignedContent)o;

      X509Certificate signer = null;
      try {
        signer = sc.verify();
        System.out.println("This message is signed from: "+signer.getSubjectDN());
      } catch (SignatureException ex) {
        throw new SignatureException("Signature verification error: " + ex.toString());
      }
      
      parse(sc.getContent());
      
    } else if (o instanceof CompressedContent) {
      
      System.out.println("The content of this message is compressed.");
      CompressedContent compressed = (CompressedContent)o;
      parse(compressed.getContent());  
    
    } else if (o instanceof InputStream) {

       // we already know that the content is an input stream (thus we must not check for other content values)
      System.out.println("Content is just an input stream.");
      System.out.println("---------------------------");
      InputStream is = (InputStream)o;
      // read content 
      if (readContent(is) == false) {
        throw new Exception("Content not equal to original one!");
      }
      
    } else {
      throw new Exception("Unexpected object!");
    }
  }
  
  
  /**
   * Reads the content from the given input stream, writes it
   * to a temp file and then compares the tmp file with the 
   * original data file.
   * 
   * @param content the content to be written
   * 
   * @return <code>true</code> if the content is equal to the original one,
   *         <code>false</code> if it differs from the original one
   * @throws IOException
   */
  private final static boolean readContent(InputStream content) throws IOException {
    String fileName = TEST_DIR + "/tmp.dat";
    
    // file stream to which to write content
    FileOutputStream fos = null;
    // file stream from which to read content for comparison 
    FileInputStream fis = null;
    // temp file to which write / from which read content for comparison
    File file = null;
    // file stream from which to read original content for comparison 
    FileInputStream origFis = null;
    try {
      //  write to file
      System.out.println("Write content to " + fileName);
      fos = new FileOutputStream(fileName);
      InputStream in = new BufferedInputStream(content);
      OutputStream out = new BufferedOutputStream(fos);
      Util.copyStream(in,
                      out,
                      new byte[8192]);
      out.flush();
      fos.close();
      fos = null;
      
      // compare contents
      file = new File(fileName);
      fis = new FileInputStream(file);
      origFis = new FileInputStream(DATA_FILE_NAME);
      System.out.println("Compare with original content"); 
      
      boolean equal = equals(new BufferedInputStream(fis), new BufferedInputStream(origFis));
      if (equal) {
        System.out.println("Content ok");
      }
      return equal;
    } finally {
      if (origFis != null) {
        try {
          origFis.close();
        } catch (IOException ex) {
          // ignore
        }
      }
      if (fis != null) {
        try {
          fis.close();
        } catch (IOException ex) {
          // ignore
        }
        // delete tmp file
        try {
          file.delete();
        } catch (Exception ex) {
          // ignore
        }
      }
      if (fos != null) {
        try {
          fos.close();
        } catch (IOException ex) {
          // ignore
        }
      }
      
    }
  }
   
  
  
  
  /**
   * Creates a file of the given size and fills it with random
   * data. The file is written to the directory used by this
   * demo. If the directory does not exist it is created.
   * 
   * @param fileName the name of the file to be created
   * @param size the size (in bytes) of the file
   * 
   * @throws IOException if an exception occurs during creating/writing the
   *                     file
   */
  private final static void createDataFile(String fileName, int size) 
    throws IOException {
    // create output directory
    File dir = new File(TEST_DIR);
    if (dir.exists() == false) {
      dir.mkdir();
    }
    // create big data file
    System.out.println("Creating " + size + " b data file " + fileName);
    OutputStream os = null;
    try {
      Random random = new Random();
      os = new BufferedOutputStream(new FileOutputStream(fileName));
      int bufSize = 8192;
      byte[] buf = new byte[bufSize];
      int blockSize = size / bufSize;
      for (int i = 0; i < blockSize; i++) {
        random.nextBytes(buf);
        os.write(buf);
        os.flush();
      }
      // write the rest
      buf = new byte[size - blockSize * bufSize];
      random.nextBytes(buf);
      os.write(buf);
      os.flush();
      System.out.println("Data file " + fileName + " created.");
    } finally {
      if (os != null) {
        try {
          os.close();
        } catch (IOException ex) {
          // ignore
        }
      }
    }
  }
  
  /**
   * Compares the data read from the two input streams.
   * 
   * @param source1 the first input stream
   * @param source2 the second input stream
   * 
   * @return true if the data is equal, false if it is not equal
   * 
   * @throws IOException if an exception occurs
   */
  private final static boolean equals(InputStream source1, InputStream source2)
      throws IOException
  {

    boolean equals;
    int bufSize = 8192;
    if (source1 != source2) {
      if ((source1 != null) && (source2 != null)) {
        byte[] buffer1 = new byte[bufSize];
        byte[] buffer2 = new byte[bufSize];
        if (buffer1.length > buffer2.length) {
          // swap
          byte[] temp = buffer1;
          buffer1 = buffer2;
          buffer2 = temp;
        }

        equals = true;
        int bytesRead1;
        while ((bytesRead1 = source1.read(buffer1)) >= 0) {
          int bytesRead2;
          int totalBytesRead2 = 0;
          while (((bytesRead2 = source2.read(buffer2, totalBytesRead2, (bytesRead1 - totalBytesRead2))) >= 0) 
                 && (totalBytesRead2 < bytesRead1)) {
            totalBytesRead2 += bytesRead2;
          }
          if (totalBytesRead2 == bytesRead1) {
            if (!CryptoUtils.equalsBlock(buffer1, 0, buffer2, 0, bytesRead1)) {
              equals = false;
              break;
            }
          } else {
            equals = false;
            break;
          }
        }
         if (source2.read(buffer2) >= 0) {
           // there has been data left in stream 2
           equals = false;
         }
      } else {
        equals = false;
      }
    } else {
      equals = true;
    }
    
    return equals ;
  }



  /**
   * The main method.
   */
  public static void main(String[] argv) throws IOException {

    DemoSMimeUtil.initDemos();
   	(new BigSMimeMailDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
