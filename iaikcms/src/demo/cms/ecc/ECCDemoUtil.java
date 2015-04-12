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
// $Header: /IAIK-CMS/current/src/demo/cms/ecc/ECCDemoUtil.java 5     28.11.13 16:31 Dbratko $
// $Revision: 5 $

package demo.cms.ecc;


import iaik.cms.IaikProvider;
import iaik.cms.SecurityProvider;
import iaik.cms.Utils;

import java.lang.reflect.Method;
import java.security.Provider;
import java.security.Security;

/**
 * Some utilities for the ECC demos.
 */
public class ECCDemoUtil {
  
  /**
   * ECC supporting CMS SecurityProvider.
   */
  private static IaikProvider iaikEccProvider_;
  
  /**
   * Installs an ECC supporting IAIK SecurityProvider. Depending on its presence in
   * the classpath, either the new (ECCelerate) or old (IAIK-ECC) library is used.
   * 
   * @return the ECC supporting IAIK SecurityProvider
   * 
   * @throws Exception if the IAIK ECC Provider cannot be installead
   */
  public static IaikProvider installIaikEccProvider() throws Exception {
    if (iaikEccProvider_ == null) { 
      IaikProvider iaikEccProvider = null;
      Class eccelerateProviderCl = null;
      try {
        eccelerateProviderCl = Class.forName("iaik.security.ec.provider.ECCelerate");
      } catch (Throwable t) {
        // ignore; try old IAIK-ECC library
      }
      if (eccelerateProviderCl != null) {
        // new IAIK-ECC library
        Provider eccProvider = (Provider)eccelerateProviderCl.newInstance();
        Class iaikCmsEccelerateProviderCl = null;
        try {
          iaikCmsEccelerateProviderCl = Class.forName("iaik.cms.ecc.ECCelerateProvider");
        } catch (Throwable t) {
          // ignore; try old IAIK-ECC library
        }
        if (iaikCmsEccelerateProviderCl != null) {
          Security.insertProviderAt(eccProvider, 1);
          iaikEccProvider = (IaikProvider)iaikCmsEccelerateProviderCl.newInstance();
          try {
            // for the demos we disable SP80057 security strength recommendation checks
            Method[] methods = eccelerateProviderCl.getDeclaredMethods();
            Method method = eccelerateProviderCl.getDeclaredMethod("enforceSP80057Recommendations", new Class[] {boolean.class});
            method.invoke(eccelerateProviderCl, new Object[] { Boolean.FALSE });
          } catch (Throwable t) {
            // ignore; run with SP80057 recommendations enforced
          }
        }  
      }
      if (iaikEccProvider == null) {
        if (Utils.isClassAvailable("iaik.security.ecc.provider.ECCProvider")) {
          // old IAIK-ECC library   
          iaikEccProvider = (IaikProvider)Class.forName("iaik.cms.ecc.IaikEccProvider").newInstance();
        }
      }  
      if (iaikEccProvider == null) {
        throw new Exception("Cannot install ECC SecurityProvider!");
      }
      iaikEccProvider_ = iaikEccProvider;
    }  
    SecurityProvider.setSecurityProvider(iaikEccProvider_);
    return iaikEccProvider_;
  }

}


