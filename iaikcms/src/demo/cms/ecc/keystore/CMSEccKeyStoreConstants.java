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
// $Header: /IAIK-CMS/current/src/demo/cms/ecc/keystore/CMSEccKeyStoreConstants.java 10    3.07.12 13:16 Dbratko $
// $Revision: 10 $
//

package demo.cms.ecc.keystore;

/**
 * Some constants for the keystore used by the ECC demos.
 * 
 * @see demo.cms.ecc.keystore.CMSEccKeyStore
 * @see demo.cms.ecc.keystore.SetupCMSEccKeyStore
 * 
 * @author Dieter Bratko
 */
public interface CMSEccKeyStoreConstants {
  public final static String CA_ECDSA         = "CA.ECDSA";
  public final static String ECDSA_192        = "ECDSA.192";
  public final static String ECDSA_224        = "ECDSA.224";
  public final static String ECDSA_256        = "ECDSA.256";
  public final static String ECDSA_384        = "ECDSA.384";
  public final static String ECDSA_521        = "ECDSA.521";
  public final static String ECDH_192         = "ECDH.192";
  public final static String ECDH_192_        = "ECDH_.192";
  public final static String ECDH_256         = "ECDH.256";
  public final static String ECDH_256_        = "ECDH_.256";
  public final static String ECDH_384         = "ECDH.384";
  public final static String ECDH_384_        = "ECDH_.384";
  public final static String ECDH_521         = "ECDH.521";
  public final static String ECDH_521_        = "ECDH_.521";
  public final static String KS_FILENAME      = "cmsecc.keystore";
  public final static char[] KS_PASSWORD      = "topSecret".toCharArray();
  public final static String KS_DIRECTORY     = System.getProperty("user.dir");
}
   