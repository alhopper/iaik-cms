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
// $Header: /IAIK-CMS/current/src/demo/cms/authenticatedData/HMACwith3DESAuthenticatedDataDemo.java 2     21.09.09 12:59 Dbratko $
// $Revision: 2 $

package demo.cms.authenticatedData;

import iaik.asn1.structures.AlgorithmID;
import iaik.cms.CMSAlgorithmID;

import java.io.IOException;

import demo.DemoUtil;

/**
 * Demonstrates the usage of class {@link iaik.cms.AuthenticatedDataStream} and
 * {@link iaik.cms.AuthenticatedData} for recipient-specific protecting the 
 * integrity of a message using the CMS type AuthenticatedData with the
 * <code>HMACwith3DESwrap</code> algorithm for wrapping the HMAC key.
 * <p>
 * 
 * <b>Attention:</b> This demo uses Static-Static Diffie-Hellman as key management 
 * technique for providing origin authentication. The mac key is wrapped by
 * using the HMACwith3DESwrap algorithm as specified by RFC 3537. Since this 
 * algorithm is not implemented by IAIK-JCE versions prior 3.12, this demo
 * at least may require IAIK-JCE 3.12 as cryptographic service provider.
 * <p>
 * This demo requires that you have <code>iaik_esdh.jar</code>
 * (or <code>iaik_jce_full.jar</code>) in your classpath.
 * You can download iaik_esdh.jar from <a href="http://jce.iaik.tugraz.at/download/">
 * http://jce.iaik.tugraz.at/download/</a>.
 * 
 *
 * @see iaik.cms.AuthenticatedDataStream
 * @see iaik.cms.AuthenticatedData
 * 
 * @author Dieter Bratko
 */
public class HMACwith3DESAuthenticatedDataDemo extends AuthenticatedDataDemo {

  /**
   * Creates an HMACwith3DESAuthenticatedDataDemo and setups the demo certificates.
   * <br>
   * Keys and certificates are retrieved from the demo KeyStore ("cms.keystore")
   * file which has to be located in your current working directory and may be
   * created by running {@link demo.keystore.SetupCMSKeyStore
   * SetupCMSKeyStore}.
   * <br>
   * HMACwith3DESwrap is used as key wrap algorithm.
   *
   * @exception IOException if an file read error occurs
   */
  public HMACwith3DESAuthenticatedDataDemo() throws IOException {
    super((AlgorithmID)CMSAlgorithmID.cms_HMACwith3DES_wrap.clone(),
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
    (new HMACwith3DESAuthenticatedDataDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}


