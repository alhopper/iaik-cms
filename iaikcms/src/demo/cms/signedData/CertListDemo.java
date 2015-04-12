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
// $Header: /IAIK-CMS/current/src/demo/cms/signedData/CertListDemo.java 15    27.08.07 16:52 Dbratko $
// $Revision: 15 $
//

package demo.cms.signedData;

import iaik.cms.CMSCertList;
import iaik.security.provider.IAIK;
import iaik.x509.X509Certificate;

import java.io.FileInputStream;
import java.io.IOException;

import demo.DemoUtil;

/**
 * Reads a CMS (PKCS#7) certifcate list from a file.
 * <p>
 * When starting the test, you have to specify
 * the file name holding the <code>CMSCertList</code> to be parsed:
 * <pre>
 * java demo.cms.CertListDemo &lt;file name&gt;
 * </pre>
 *
 * @see iaik.cms.CMSCertList
 * 
 * @author Dieter Bratko
 */
public class CertListDemo {

  /**
   * Reads a CMS (PKCS#7) certificate chain from a file and dumps the certificates
   * stored inside.
   * <p>
   * Usage:
   * <p><code>
   * java demo.cms.CertListDemo &lt;file name&gt;
   * </code><p>
   *
   * @param arg the name of the file holding the certificate chain
   */
  public static void main(String arg[]) {

   	IAIK.addAsJDK14Provider(true);
     
    if (arg.length != 1) {
      
      System.out.println("Usage: java demo.cms.CertListDemo <CMS-certificate-chain-file>");
      
    } else {
      
      FileInputStream fis = null;
      try {
        fis = new FileInputStream(arg[0]);
    	CMSCertList cmsCertList = new CMSCertList(fis);
        X509Certificate[] certs = cmsCertList.getX509Certificates();

        for (int i = 0; i < certs.length; i++) {
           System.out.println(certs[i]);
        }   

      } catch (Exception ex) {
        System.out.println("Error reading certificates: "+ ex.toString());
      } finally {
        if (fis != null) {
          try {
            fis.close();
          } catch (IOException ex) {
            // ignore
          } 
        }    
      }
      
    }
    System.out.println();
    DemoUtil.waitKey();
  }	
}