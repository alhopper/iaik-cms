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
// $Header: /IAIK-CMS/current/src/demo/DemoAll.java 46    13.08.13 16:56 Dbratko $
// $Revision: 46 $
//

package demo;

import iaik.asn1.structures.AlgorithmID;
import iaik.cms.Utils;

import java.io.File;
import java.io.IOException;

import demo.cms.authenticatedData.AuthenticatedDataDemo;
import demo.cms.authenticatedData.AuthenticatedDataOutputStreamDemo;
import demo.cms.basic.CMSDemo;
import demo.cms.compressedData.CompressedDataDemo;
import demo.cms.compressedData.CompressedDataOutputStreamDemo;
import demo.cms.data.DataDemo;
import demo.cms.digestedData.DigestedDataDemo;
import demo.cms.digestedData.DigestedDataOutputStreamDemo;
import demo.cms.ecc.ECCDemoUtil;
import demo.cms.encryptedData.EncryptedDataDemo;
import demo.cms.encryptedData.EncryptedDataOutputStreamDemo;
import demo.cms.envelopedData.ArcFourEnvelopedDataDemo;
import demo.cms.envelopedData.CAST128EnvelopedDataDemo;
import demo.cms.envelopedData.EncryptedContentInfoDemo;
import demo.cms.envelopedData.EnvelopedDataDemo;
import demo.cms.envelopedData.EnvelopedDataOutputStreamDemo;
import demo.cms.envelopedData.OaepEnvelopedDataDemo;
import demo.cms.envelopedData.RC2EnvelopedDataDemo;
import demo.cms.pkcs7cms.PKCS7CMSDataDemo;
import demo.cms.pkcs7cms.PKCS7CMSDigestedDataDemo;
import demo.cms.pkcs7cms.PKCS7CMSEncryptedContentInfoDemo;
import demo.cms.pkcs7cms.PKCS7CMSEncryptedDataDemo;
import demo.cms.pkcs7cms.PKCS7CMSEnvelopedDataDemo;
import demo.cms.pkcs7cms.PKCS7CMSSignedDataDemo;
import demo.cms.signedAndEnvelopedData.SignedAndEnvelopedDataDemo;
import demo.cms.signedData.CounterSignatureDemo;
import demo.cms.signedData.PssSignedDataDemo;
import demo.cms.signedData.SignedDataDemo;
import demo.cms.signedData.SignedDataDemoWithAdditionalSignerInfo;
import demo.cms.signedData.SignedDataOutputStreamDemo;
import demo.cms.signedData.SignedDataStreamDemoWithAdditionalSignerInfo;
import demo.keystore.CMSKeyStoreConstants;
import demo.keystore.SetupCMSKeyStore;
import demo.smime.basic.BinarySignedDemo;
import demo.smime.basic.CMSStreamDemo;
import demo.smime.basic.ProcessMessageDemo;
import demo.smime.basic.SMimeDemo;
import demo.smime.basic.SMimeV3Demo;
import demo.smime.ess.MLADemo;
import demo.smime.ess.SignedReceiptDemo;
import demo.smime.ess.SigningCertificateDemo;
import demo.smime.ess.TripleWrappingDemo;

/**
 * This class runs all available demos.
 * 
 * @author Dieter Bratko
 */
public class DemoAll implements CMSKeyStoreConstants {

  /**
   * Start all tests.
   */
  public void start() throws Exception {
    
    File keystore = new File(CMSKeyStoreConstants.KS_FILENAME);
    if (!keystore.exists()) {
      System.out.println("Can't find '"+CMSKeyStoreConstants.KS_FILENAME+"'!");
      System.out.println("Create new keystore...");

      SetupCMSKeyStore.start();
    }
    
    // cms demos
    (new CMSDemo()).start();
    (new DataDemo()).start();
    (new DigestedDataDemo()).start();
    (new EncryptedDataDemo()).start();
    if (Utils.isClassAvailable("iaik.security.dh.ESDHPublicKey")) {
      // require ESDH
      (new EnvelopedDataDemo()).start();
      if (DemoUtil.getIaikProviderVersion() >= 3.12) { 
        (new AuthenticatedDataDemo()).start();
      }
      if (DemoUtil.getIaikProviderVersion() >= 3.14) {
        (new demo.cms.envelopedData.AESEnvelopedDataDemo()).start();
        (new EnvelopedDataDemo((AlgorithmID)AlgorithmID.aes192_CBC.clone(),
                               (AlgorithmID)AlgorithmID.cms_aes192_wrap.clone(),
                               192)).start();
        (new EnvelopedDataDemo((AlgorithmID)AlgorithmID.aes256_CBC.clone(),
                               (AlgorithmID)AlgorithmID.cms_aes256_wrap.clone(),
                               256)).start();
      }
      if (DemoUtil.getIaikProviderVersion() > 3.18) {
        (new demo.cms.envelopedData.CamelliaEnvelopedDataDemo()).start();
        (new EnvelopedDataDemo((AlgorithmID)AlgorithmID.camellia192_CBC.clone(),
                               (AlgorithmID)AlgorithmID.cms_camellia192_wrap.clone(),
                                192)).start();
        (new EnvelopedDataDemo((AlgorithmID)AlgorithmID.camellia256_CBC.clone(),
                               (AlgorithmID)AlgorithmID.cms_camellia256_wrap.clone(),
                               256)).start();
        (new demo.cms.authenticatedData.HMACwithAESAuthenticatedDataDemo()).start();
      }
    }
    (new SignedDataDemo()).start();
    (new CompressedDataDemo()).start();
    (new EncryptedContentInfoDemo()).start();
    (new SignedAndEnvelopedDataDemo()).start();
    (new CAST128EnvelopedDataDemo()).start();
    (new RC2EnvelopedDataDemo()).start();
    (new ArcFourEnvelopedDataDemo()).start();
    
    // run separatly since stores encryption result to a file   
    //(new FileEncryptionDemo()).start();
    
    (new PKCS7CMSDataDemo()).start();
    (new PKCS7CMSDigestedDataDemo()).start();
    (new PKCS7CMSEncryptedDataDemo()).start();
    (new PKCS7CMSEnvelopedDataDemo()).start();
    (new PKCS7CMSSignedDataDemo()).start();
    (new PKCS7CMSEncryptedContentInfoDemo()).start();
    (new PssSignedDataDemo()).start();
    (new OaepEnvelopedDataDemo()).start();
    (new SignedDataDemoWithAdditionalSignerInfo()).start();
    (new SignedDataStreamDemoWithAdditionalSignerInfo()).start();
    (new CounterSignatureDemo()).start();
    (new EnvelopedDataOutputStreamDemo()).start();
    (new SignedDataOutputStreamDemo()).start();
    (new EncryptedDataOutputStreamDemo()).start();
    (new DigestedDataOutputStreamDemo()).start();
    if ((DemoUtil.getIaikProviderVersion() >= 3.12) &&
        (Utils.isClassAvailable("iaik.security.dh.ESDHPublicKey"))) {
      (new AuthenticatedDataOutputStreamDemo()).start();
    }  
    (new CompressedDataOutputStreamDemo()).start();
    
    if (Utils.isClassAvailable("iaik.security.dh.ESDHPublicKey")) {
      // requires ESDH
      (new CMSStreamDemo()).start();
    }  
    
    // smime demos
    (new SMimeDemo()).start();
    if (Utils.isClassAvailable("iaik.security.dh.ESDHPublicKey")) {
      // requires ESDH
      (new SMimeV3Demo()).start();
    }
    if (DemoUtil.getIaikProviderVersion() > 3.18) {
      (new demo.smime.basic.SMimeCamelliaDemo()).start();
      (new demo.smime.basic.SMimeV3CamelliaDemo()).start();
    }
    (new ProcessMessageDemo()).start();
    (new BinarySignedDemo()).start();
    
    // run separatly because it creates big (temporary) files
    // (new BigSMimeMailDemo()).start();
    
    (new SigningCertificateDemo()).start();
    (new TripleWrappingDemo()).start();
    (new SignedReceiptDemo()).start();

    // run separatly (uses Swing Dialog)
    //    
    //    if (Utils.isClassAvailable("javax.swing.JOptionPane")) {
    //      (new SecurityLabelDemo()).start();
    //    }
    
    (new MLADemo()).start();
    
    
    // TSP demos (the IAIK TSP library must be in the classpath)
    if ((Utils.isClassAvailable("iaik.tsp.TimeStampReq")) && (DemoUtil.getIaikProviderVersion() >= 3.14)  ) {
      (new demo.cms.tsp.TimeStampDemo()).start();
    }
    
    // ECC demos (IAIK ECC provider must be in the classpath)
    if ((Utils.isClassAvailable("iaik.security.ecc.provider.ECCProvider")) ||
        (Utils.isClassAvailable("iaik.security.ec.provider.ECProvider"))) {
      // add ECC provider    
      ECCDemoUtil.installIaikEccProvider();
      // CMS
      (new demo.cms.ecc.ECDSASignedDataDemo()).start();
      (new demo.cms.ecc.ECDHEnvelopedDataDemo()).start();
      // S/MIME
      (new demo.smime.ecc.SMimeEccDemo()).start();
      if (DemoUtil.getIaikProviderVersion() > 3.13) {
        (new demo.smime.ecc.SMimeEccSuiteBDemo()).start();
      }  
    }  
    
  }

  /**
   * Performs all tests.
   */
  public static void main(String arg[]) throws IOException {

    DemoSMimeUtil.initDemos();

    try {
      (new DemoAll()).start();
      System.out.println("All demos O.K.!!!");
    } catch(Exception ex) {
      System.out.println("There were errors: " + ex.toString());
      ex.printStackTrace();
    }
    
    DemoUtil.waitKey();
    
  }
}
