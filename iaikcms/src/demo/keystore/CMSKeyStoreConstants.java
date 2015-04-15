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
// $Header: /IAIK-CMS/current/src/demo/keystore/CMSKeyStoreConstants.java 15    16.04.09 12:59 Dbratko $
// $Revision: 15 $
//

package demo.keystore;

/**
 * Some constants for the keystore used by the demos.
 * 
 * @see demo.keystore.CMSKeyStore
 * @see demo.keystore.SetupCMSKeyStore
 * 
 * @author Dieter Bratko
 */
public interface CMSKeyStoreConstants {
  public final static String CA_RSA           = "CA.RSA";
  public final static String CA_DSA           = "CA.DSA";
  public final static String CA_EC 			  = "CA.EC";
  public final static String RSA_512_SIGN     = "RSA_SIGN.512";
  public final static String RSA_512_CRYPT    = "RSA_CRYPT.512";
  public final static String RSA_1024_SIGN    = "RSA_SIGN.1024";
  public final static String RSA_1024_CRYPT   = "RSA_CRYPT.1024";
  public final static String RSA_1024_CRYPT_  = "RSA_CRYPT_.1024";
  public final static String RSA_2048_SIGN    = "RSA_SIGN.2048";
  public final static String RSA_2048_CRYPT   = "RSA_CRYPT.2048";
  public final static String DSA_512          = "DSA.512";
  public final static String DSA_1024         = "DSA.1024";
  public final static String DSA_2048         = "DSA.2048";  // with SHA224
  public final static String DSA_3072         = "DSA.3072";  // with SHA256  
  public final static String ESDH_512         = "ESDH.512";
  public final static String ESDH_1024        = "ESDH.1024";
  public final static String ESDH_1024_       = "ESDH_.1024";
  public final static String ESDH_2048        = "ESDH.2048";
  public final static String SSDH_1024        = "SSDH.1024";
  public final static String SSDH_1024_       = "SSDH_.1024";
  public final static String EC_256_SIGN  	  = "EC_SIGN.256";
  public final static String EC_256_CRYPT     = "EC_CRYPT.256";
  public final static String ECDSA_256		  = "ECDSA.256";
  public final static String TSP_SERVER       = "TSP.SERVER";
  public final static String KS_FILENAME      = "cms.keystore";
  public final static char[] KS_PASSWORD      = "topSecret".toCharArray();
  public final static String KS_DIRECTORY     = System.getProperty("user.dir");
}
   