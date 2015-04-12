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
// $Header: /IAIK-CMS/current/src/demo/cms/envelopedData/CamelliaEnvelopedDataDemo.java 5     13.10.09 17:05 Dbratko $
// $Revision: 5 $
//


package demo.cms.envelopedData;

import iaik.asn1.structures.AlgorithmID;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import demo.DemoUtil;


/**
 * Demonstrates the usage of class {@link iaik.cms.EnvelopedDataStream} and
 * {@link iaik.cms.EnvelopedData} for encrypting data using the CMS type
 * EnvelopedData with the Camellia cipher algorithm.
 * <br>
 * Camellia is used for both content encryption and content encryption key 
 * wrapping (according to RFC 3657).
 * <p>
 * This demo creates an EnvelopedData object and subsequently shows several
 * ways that may be used for decrypting the content for some particular 
 * recipient.
 * <p>
 * Keys and certificates are retrieved from the demo KeyStore ("cms.keystore") 
 * which has to be located in your current working directory and may be
 * created by running the {@link demo.keystore.SetupCMSKeyStore
 * SetupCMSKeyStore} program.
 * <p>
 * This demo requires an IAIK-JCE version &gt;= 3.18.
 * 
 * @see iaik.cms.EnvelopedDataStream
 * @see iaik.cms.EnvelopedData
 * @see iaik.cms.RecipientInfo
 * @see iaik.cms.KeyTransRecipientInfo
 * @see iaik.cms.KeyAgreeRecipientInfo
 * @see iaik.cms.KEKRecipientInfo
 * 
 * @author Dieter Bratko
 */
public class CamelliaEnvelopedDataDemo extends EnvelopedDataDemo {

  
  /**
   * Creates an CamelliaEnvelopedDataDemo and setups the demo certificates.
   * <br>
   * Keys and certificates are retrieved from the demo KeyStore ("cms.keystore")
   * file which has to be located in your current working directory and may be
   * created by running {@link demo.keystore.SetupCMSKeyStore
   * SetupCMSKeyStore}.
   * <br>
   * Camellia and Camellia KeyWrap are used for content encryption and
   * content encryption key wrapping.
   *
   * @exception IOException if an file read error occurs
   * @exception NoSuchAlgorithmException if the requested algorithms are not supported
   */
  public CamelliaEnvelopedDataDemo() throws IOException, NoSuchAlgorithmException {
    super((AlgorithmID)AlgorithmID.camellia128_CBC.clone(),
         (AlgorithmID)AlgorithmID.cms_camellia128_wrap.clone(),
         128);
  }
      
  /**
   * Main method.
   *
   * @exception IOException
   *            if an I/O error occurs when reading required keys
   *            and certificates from files
   */
  public static void main(String argv[]) throws Exception {
    double iaikProviderVersion = DemoUtil.getIaikProviderVersion();
    if (iaikProviderVersion <= 3.18) {
      System.err.println("This demo requires a IAIK provider version > 3.18! Your IAIK provider version is " + iaikProviderVersion + ".");
    } else {  
     	DemoUtil.initDemos();
      // Camellia with 128 bit keys 
      System.out.println("\n***** Camellia-128 demo *****\n");
      (new CamelliaEnvelopedDataDemo()).start();
      // Camellia with 192 bit keys
      System.out.println("\n***** Camellia-192 demo *****\n");
      (new EnvelopedDataDemo((AlgorithmID)AlgorithmID.camellia192_CBC.clone(),
                             (AlgorithmID)AlgorithmID.cms_camellia192_wrap.clone(),
                              192)).start();
      // Camellia with 256 bit keys
      System.out.println("\n***** Camellia-256 demo *****\n");
      (new EnvelopedDataDemo((AlgorithmID)AlgorithmID.camellia256_CBC.clone(),
                             (AlgorithmID)AlgorithmID.cms_camellia256_wrap.clone(),
                              256)).start();
  
      System.out.println("\nReady!");
    }  
    DemoUtil.waitKey();
  }
}
