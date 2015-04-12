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
// $Header: /IAIK-CMS/current/src/demo/cms/envelopedData/TripleDESEnvelopedDataDemo.java 2     13.10.09 17:05 Dbratko $
// $Revision: 2 $
//


package demo.cms.envelopedData;

import iaik.asn1.structures.AlgorithmID;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import demo.DemoUtil;


/**
 * Demonstrates the usage of class {@link iaik.cms.EnvelopedDataStream} and
 * {@link iaik.cms.EnvelopedData} for encrypting data using the CMS type
 * EnvelopedData with the TripleDES (DES-EDE3) cipher algorithm.
 * <br>
 * TripleDES is used for both content encryption (according to RFC 3370) and
 * content encryption key wrapping (according to RFC 3217).
 * <p>
 * This demo creates an EnvelopedData object and subsequently shows several
 * ways that may be used for decrypting the content for some particular 
 * recipient.
 * <p>
 * Keys and certificates are retrieved from the demo KeyStore ("cms.keystore") 
 * which has to be located in your current working directory and may be
 * created by running the {@link demo.keystore.SetupCMSKeyStore
 * SetupCMSKeyStore} program.
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
public class TripleDESEnvelopedDataDemo extends EnvelopedDataDemo {

  
  /**
   * Creates an TripleDESEnvelopedDataDemo and setups the demo certificates.
   * <br>
   * Keys and certificates are retrieved from the demo KeyStore ("cms.keystore")
   * file which has to be located in your current working directory and may be
   * created by running {@link demo.keystore.SetupCMSKeyStore
   * SetupCMSKeyStore}.
   * <br>
   * TripleDES and TripleDES KeyWrap are used for content encryption and
   * content encryption key wrapping.
   *
   * @exception IOException if an file read error occurs
   * @exception NoSuchAlgorithmException if the requested TripleDES or TripleDES KeyWrap 
   *                                     algorithms are not supported
   */
  public TripleDESEnvelopedDataDemo() throws IOException, NoSuchAlgorithmException {
    super((AlgorithmID)AlgorithmID.des_EDE3_CBC.clone(),
          (AlgorithmID)AlgorithmID.cms_3DES_wrap.clone(),
          192);
  }
      
  /**
   * Main method.
   *
   * @exception IOException
   *            if an I/O error occurs when reading required keys
   *            and certificates from files
   */
  public static void main(String argv[]) throws Exception {

   	DemoUtil.initDemos();
    (new TripleDESEnvelopedDataDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
