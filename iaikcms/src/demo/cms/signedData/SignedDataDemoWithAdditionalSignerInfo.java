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
// $Header: /IAIK-CMS/current/src/demo/cms/signedData/SignedDataDemoWithAdditionalSignerInfo.java 16    23.08.13 14:29 Dbratko $
// $Revision: 16 $
//

package demo.cms.signedData;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.cms.IssuerAndSerialNumber;
import iaik.cms.SignedData;
import iaik.cms.SignerInfo;
import iaik.cms.attributes.CMSContentType;
import iaik.cms.attributes.SigningTime;
import iaik.x509.X509Certificate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import demo.DemoUtil;
import demo.keystore.CMSKeyStore;

/**
 * This class shows how to use the non-stream based {@link iaik.cms.SignedData SignedData} 
 * implmentation to add a new SignerInfo to an existing, parsed SignedData object.
 * 
 * @author Dieter Bratko
 */
public class SignedDataDemoWithAdditionalSignerInfo {

  String testMessage;

  public SignedDataDemoWithAdditionalSignerInfo() {
    
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                      SignedDataDemoWithAdditionalSignerInfo                    *");
    System.out.println("*    (shows how to add a new signer to an already existing SignedData object)    *");
    System.out.println("**********************************************************************************");
    System.out.println();
    
    testMessage = "This is a test of the CMS implementation!";
  }

  /**
   * Verifies a given SignedData object which is read from the given input stream.
   *
   * @param is an input stream holding the SignedData object
   *
   * @exception Exception if an error occurs when verifying the SignedData
   */
  private void verify(InputStream is) throws Exception {

    System.out.println("\nVerify the SignedData...");
    // read the SignedData from the given input stream
    SignedData signedData = new SignedData(is);
    // get the content
    byte[] content = signedData.getContent();
    // and show it
    System.out.println("Content of SignedData: "+new String(content));

    // print the certificates included
    System.out.println("Certificates included:");
    Certificate[] certs = signedData.getCertificates();
    try {
      for (int i = 0; i < certs.length; i++)
        System.out.println(certs[i]);
    } catch (Exception ex) {
      ex.printStackTrace();
    }
                
    // print the signers included
    System.out.println("Signers included:");
    SignerInfo[] signerInfos = signedData.getSignerInfos();

    for (int i = 0; i < signerInfos.length; i++) {
      X509Certificate cert = signedData.verify(i);
      System.out.println("Signer: " + cert.getSubjectDN());
      System.out.println(signerInfos[i].toString(true));
    }
  }
    
  /**
   * Creates a new SignedData object.
   *
   * @param os the output stream where the created object shall be written to
   * @param message the content for the SignedData
   * @param size specifies which private key/certificate to use from the KeyStore
   *
   * @exception Exception if an error occurs when creating the SignedData object
   */
  private void create(OutputStream os, String message, int size) throws Exception {

    System.out.println("\nCreate a new SignedData with content: "+message);
    // get the certificate chain from teh KeyStore
    X509Certificate[] certificates = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, size);
    // create the SignedData
    SignedData signedData = new SignedData(message.getBytes(), iaik.cms.SignedData.IMPLICIT);
    // set teh certificates
    signedData.setCertificates(certificates);
    // add a signer
    addSigner(signedData, size);
    // and write it the given output stream
    signedData.writeTo(os);
    os.close();
  }

  /**
   * Adds a new Signer to a given SignedData.
   *
   * @param is the input stream holding the existing SignedData object
   * @param size specifies which private key/certificate to use from the KeyStore
   */
  private ByteArrayOutputStream add(InputStream is, int size) throws Exception {

    System.out.println("Adding a signature to an existing SignedData...");
    // read the existing SignedData from the given InputStream
    SignedData signedData = new SignedData(is);
    // print the content
    byte[] content = signedData.getContent();
    System.out.println("Existing content is: " + new String(content));
    
    // add another signer
    addSigner(signedData, size);

    // create a new output stream and save it
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    signedData.writeTo(os);

    is.close();
    os.close();

    // return the output stream which contains the new SignedData
    return os;
  }

  /**
   * Adds the new signer.
   *
   * @param signedData the SignedData where the new signer shall be added
   * @param size specifies which private key/certificate to use from the KeyStore
   */
  private void addSigner(SignedData signedData, int size) throws Exception {
        
    // get new certificate and private key
    X509Certificate cert = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, size)[0];
    PrivateKey privateKey = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, size);
        
    // add to the existing list of certificates
    Certificate[] certs = signedData.getCertificates();
    Certificate[] newCerts = new Certificate [certs.length + 1];
    System.arraycopy(certs, 0, newCerts, 0, certs.length);
    newCerts[certs.length] = cert;
    // set the new certificate list
    signedData.setCertificates(newCerts);
        
    // create a new SignerInfo
    SignerInfo signerInfo = new SignerInfo(new IssuerAndSerialNumber(cert), 
                                           (AlgorithmID)AlgorithmID.sha256.clone(),
                                           privateKey);
    // define some attributes
    Attribute[] attributes = { 
      new Attribute(new CMSContentType(ObjectID.cms_data)),
      new Attribute(new SigningTime())
    };
    // set the attributes
    signerInfo.setSignedAttributes(attributes);
    // and add the new signer
    signedData.addSignerInfo(signerInfo);
  }
  
  /**
   * Starts the test.
   */
  public void start() {

    try {
      // output stream for storing the signed data
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      // create a new SignedData
      create(os, testMessage, CMSKeyStore.SZ_1024_SIGN);
      // verify it      
      verify(new ByteArrayInputStream(os.toByteArray()));
      // add another signer
      os = add(new ByteArrayInputStream(os.toByteArray()), CMSKeyStore.SZ_2048_SIGN);
      // and verify it again
      verify(new ByteArrayInputStream(os.toByteArray()));

   	} catch (Exception ex) {
   	  ex.printStackTrace();
   	  throw new RuntimeException(ex.toString());
   	}
  }
    
  /**
   * Main method.
   * 
   * @exception IOException 
   *            if an I/O error occurs when reading required keys
   *            and certificates from files
   */
  public static void main(String argv[]) throws IOException {

    DemoUtil.initDemos();
    (new SignedDataDemoWithAdditionalSignerInfo()).start();
       
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
