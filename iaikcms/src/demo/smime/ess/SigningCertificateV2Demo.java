package demo.smime.ess;

import iaik.cms.CMSException;
import iaik.cms.SignerInfo;
import iaik.smime.ess.SigningCertificate;
import iaik.smime.ess.SigningCertificateV2;

import java.io.IOException;
import java.security.cert.Certificate;

import demo.DemoUtil;

/**
 * Demonstrates how to add and parse a {@link iaik.smime.ess.SigningCertificateV2
 * SigningCertificateV2} attribute to the SignerInfo of a {@link iaik.cms.SignedDataStream} or
 * {@link iaik.cms.SignedData} object. The SigningCertificateV2 attributes maybe used
 * to include certificate identification information into the signed attributes of a 
 * CMS {@link iaik.cms.SignerInfo SignerInfo} object. It has been introduced by 
 * RFC 5035 to allow to use the {@link iaik.smime.ess.SigningCertificate
 * SigningCertificate} attribute with other hash algorithms than SHA-1.
 *
 * @see iaik.smime.ess.SigningCertificate
 * @see iaik.smime.ess.SigningCertificateV2
 * @see iaik.cms.SignerInfo
 * @see iaik.cms.SignedDataStream
 * @see iaik.cms.SignedData
 * 
 * @author Dieter Bratko
 */
public class SigningCertificateV2Demo extends SigningCertificateDemo {

  /**
   * Setups the demo certificate chains.
   * 
   * Keys and certificate are retrieved from the demo KeyStore.
   * 
   * @exception IOException if an file read error occurs
   */
  public SigningCertificateV2Demo() throws IOException {
    super();
  }
  
  /**
   * Creates a SigningCertificateV2 attribute for the given certificates.
   * 
   * @param certs the certificates for which to create the SigningCertificateV2
   *              attribute
   *              
   * @return the SigningCertificate attribute just created             
   *              
   * @exception CMSException if an error occurs when creating the
   *                      SigningCertificateV2 attribute             
   */
  protected SigningCertificate createSigningCertificate(Certificate[] certs) 
    throws CMSException {
    
    try {
      // we use the default hash algorithm (SHA-256)
      return new SigningCertificateV2(certs, true);
    } catch (Exception ex) {
      throw new CMSException("Error creating SigningCertificateV2 attribute: " + ex.toString());
    }
  }
  
  /**
   * Gets the SigningCertificateV2 attribute from the given SignerInfo.
   * 
   * @param signerInfo the SignerInfo from which to get the
   *                   SigningCertificateV2 attribute
   *                   
   * @return the SigningCertificateV2 attribute, or <code>null</code>
   *         if no SigningCertificate attribute is included  
   *         
   * @exception CMSException if an error occurs when getting the
   *                         SigningCertificateV2 attribute                              
   */
  protected SigningCertificate getSigningCertificate(SignerInfo signerInfo)
    throws CMSException {
    
    return signerInfo.getSigningCertificateV2Attribute();
  }
  
  /**
   * Prints some header lines to System.out.
   */
  protected void printHeader() {
    System.out.println();
    System.out.println("**********************************************************************************");
    System.out.println("*                       SigningCertificateV2Demo demo                            *");
    System.out.println("*          (shows the usage of the ESS SigningCertificateV2 attribute)           *");
    System.out.println("**********************************************************************************");
    System.out.println();
  }

  /**
   * The main method.
   * 
   * @exception IOException 
   *            if an I/O error occurs when reading required keys
   *            and certificates from files
   */
  public static void main(String[] args) throws Exception {
    DemoUtil.initDemos();
    (new SigningCertificateV2Demo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();

  }

}
