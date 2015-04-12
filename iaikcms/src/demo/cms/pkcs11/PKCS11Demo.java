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
// $Header: /IAIK-CMS/current/src/demo/cms/pkcs11/PKCS11Demo.java 7     12.07.12 11:29 Dbratko $
// $Revision: 7 $

package demo.cms.pkcs11;

import iaik.cms.SecurityProvider;
import iaik.pkcs.pkcs11.provider.Constants;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.security.provider.IAIK;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.Properties;

/**
 * Base class for PKCS#11 Demos.
 * 
 * @author Dieter Bratko
 */
public abstract class PKCS11Demo {
  
  /**
   * Module name (native PKCS#11 module of the cryptographic hardware.
   * It may be necessary to provide the file with the full path, if the
   * module is not in the search path of the system).
   */
  protected String moduleName_ ;
  
  /**
   * The user pin for the token key store.
   */
  protected char[] userPin_;

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 iaikPkcs11Provider_;

  /**
   * The IAIK JCE software provider.
   */
  protected IAIK iaikSoftwareProvider_;
  
  /**
   * The key store that represents the token (smart card) contents.
   */
  protected KeyStore tokenKeyStore_;
  
  /**
   * Creates a PKCS11Demo object for the given module name.
   * 
   * @param moduleName the name of the module
   * @param userPin the user-pin (password) for the TokenKeyStore
   *                (may be <code>null</code> to pou-up a dialog asking for the pin)
   */
  public PKCS11Demo(String moduleName,
                    char[] userPin) {
    
    if (moduleName == null) {
      throw new NullPointerException("moduleName must not be null!");
    }
    
    moduleName_ = moduleName;
    userPin_ = userPin;
    
    
    // check if we already have an installed provider for the requested module
    int count = IAIKPkcs11.getProviderInstanceCount();
    for (int i = 1; i <= count; i++) {
      IAIKPkcs11 pkcs11Prov = IAIKPkcs11.getProviderInstance(i);
      if (pkcs11Prov != null) {
        String module = pkcs11Prov.getProperties().getProperty(Constants.PKCS11_NATIVE_MODULE);
        if ((module != null) && (moduleName.equalsIgnoreCase(module))) {
          iaikPkcs11Provider_ = pkcs11Prov;
          break;
        }
      }  
    }
    
    if (iaikPkcs11Provider_ == null) {      
      // install IAIK PKCS#11 Provider
      Properties pkcs11ProviderConfig = new Properties();
      pkcs11ProviderConfig.put(Constants.PKCS11_NATIVE_MODULE, moduleName_);
      iaikPkcs11Provider_ = new IAIKPkcs11(pkcs11ProviderConfig);
    }  

    //IAIKPkcs11.insertProviderAtForJDK14(iaikPkcs11Provider__, 1); // add IAIK PKCS#11 JCE provider as first, use JDK 1.4 bug workaround
    Security.addProvider(iaikPkcs11Provider_);
    
    // set CMS security provider
    IaikPkcs11SecurityProvider pkcs11CmsSecurityProvider = new IaikPkcs11SecurityProvider(iaikPkcs11Provider_);
    SecurityProvider.setSecurityProvider(pkcs11CmsSecurityProvider);

    System.out.println("Installed crypto providers:");
    System.out.println();
    Provider[] providers = Security.getProviders();
    for (int i = 0; i < providers.length; i++) {
      Provider provider = providers[i];
      System.out.println("Provider " + (i  +1) + ": " + provider.getName() + "  version: " + provider.getVersion());
    }
  }
  
  /**
   * This method gets the key store of the PKCS#11 provider and stores
   * a reference at<code>pkcs11ClientKeystore_</code>.
   *
   * @exception GeneralSecurityException If anything with the provider fails.
   * @exception IOException If loading the key store fails.
   */
  public void getKeyStore() throws GeneralSecurityException, IOException
  {
    // with this call we just get an uninitialized PKCS#11 key store, it is not bound to a
    // specific IAIKPkcs11 provider instance after this call, even if you specify the provider
    // at this call. this is a limitation of JCA KeyStore concept. the KeyStoreSPI object
    // has no chance to get its own provider instance.
    KeyStore tokenKeyStore = null;
    try {
      tokenKeyStore = KeyStore.getInstance("PKCS11KeyStore", iaikPkcs11Provider_.getName());
    } catch (NoSuchProviderException ex) {
      throw new GeneralSecurityException(ex.toString());
    }

    if (tokenKeyStore == null) {
      System.out.println("Got no key store. Ensure that the provider is properly configured and installed.");
      System.exit(0);
    }
    try {
      tokenKeyStore.load(null, userPin_); // this call binds the keystore to the first instance of the IAIKPkcs11 provider
    } catch (NoSuchAlgorithmException ex) {
      throw new GeneralSecurityException(ex.toString());
    }


    tokenKeyStore_ = tokenKeyStore;
  }

}


