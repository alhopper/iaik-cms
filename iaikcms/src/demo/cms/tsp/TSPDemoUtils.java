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
// $Header: /IAIK-CMS/current/src/demo/cms/tsp/TSPDemoUtils.java 7     3.07.12 13:35 Dbratko $
// $Revision: 7 $
//

package demo.cms.tsp; 

import iaik.asn1.CodingException;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.cms.CMSException;
import iaik.cms.SignerInfo;
import iaik.smime.attributes.SignatureTimeStampToken;
import iaik.tsp.MessageImprint;
import iaik.tsp.PKIFailureInfo;
import iaik.tsp.PKIStatus;
import iaik.tsp.PKIStatusInfo;
import iaik.tsp.TSTInfo;
import iaik.tsp.TimeStampReq;
import iaik.tsp.TimeStampResp;
import iaik.tsp.TimeStampToken;
import iaik.tsp.TspException;
import iaik.tsp.transport.http.TspHttpClient;
import iaik.tsp.transport.http.TspHttpResponse;
import iaik.utils.CryptoUtils;
import iaik.x509.X509Certificate;
import iaik.x509.X509ExtensionInitException;
import iaik.x509.extensions.ExtendedKeyUsage;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Random;

/**
 * Some utils for creating and sending time stamp requests, 
 * validating responses and adding time stamp token attributes.
 * Used by the TSP demo.
 * 
 * 
 * @see TimeStampDemo
 * @see TimeStampListener
 * 
 * @author Dieter Bratko
 */
public class TSPDemoUtils {
  
  /**
   * Creates a TimeStampRequest for the given SignerInfo.
   * 
   * @param signerInfo the SignerInfo to be time stamped
   * @param reqPolicy the policy of the TSA from which to get a response,
   *                  maybe <code>null</code> if we accept any TSA
   * 
   * @return the time stamp request just created
   * 
   * @exception TspException if some error occurs during time stamp creation
   */
  public static TimeStampReq createRequest(SignerInfo signerInfo,
                                           ObjectID reqPolicy)
    
    throws TspException {
    
    // we have to time stamp the signature value
    byte[] signatureValue = signerInfo.getSignatureValue();
    // calculate the MessageImprint
    AlgorithmID hashAlg = (AlgorithmID)AlgorithmID.sha1.clone();
    MessageDigest md = null;
    try {
      md = hashAlg.getMessageDigestInstance();
    } catch (NoSuchAlgorithmException ex) {
      throw new TspException("Cannot calculate MessageImprint! Algorithm SHA-1 not supported!"); 
    }  
    byte[] toBeTimeStamped = md.digest(signatureValue);
    MessageImprint imprint = new MessageImprint(hashAlg, toBeTimeStamped);
    //Create a new TimeStampReq
    TimeStampReq request = new TimeStampReq();
    //set the imprint
    request.setMessageImprint(imprint);
    //request the TSA to include its certificate chain into the response
    request.setCertReq(true);
    if (reqPolicy != null) {
      // request some particular TSA policy?
      request.setTSAPolicyID(reqPolicy); 
    }  
    // set a Nonce
    BigInteger nonce = new BigInteger(64, new Random());
    request.setNonce(nonce);
    return request;
  }
  
  /**
   * Sends the given time stamp request to the given TSA.
   * 
   * @param request the time stamp request to be sent to the TSA
   * @param tsaUrl the URL of the time stamp authority from which to
   *               get the time stamp 
   * 
   * @exception TspException if an error occurs during sending the request to the TSA (e.g.
   *                         connecting to the TSA fails, ...)
   * @exception NullPointerException if <code>request</code> or <code>tsaUrl</code>
   *                                 are <code>null</code>                                          
   */
  public static TimeStampResp sendRequest(TimeStampReq request, 
                                          String tsaUrl)
    
    throws TspException {
    
    if (request == null) {
      throw new NullPointerException("Time stamp request must not be null!");
    }
    if (tsaUrl == null) {
      throw new NullPointerException("TSA url must not be null!");
    }
      
    try {
      // send the request to the TSA
      TspHttpClient tspHttpClient = new TspHttpClient(new URL(tsaUrl));
      TspHttpResponse tspHttpResponse = tspHttpClient.sendRequest(request);
      if (tspHttpResponse.isErrorResponse()) {
        throw new TspException("Error connecting to TSA: " + tspHttpResponse.getErrorMsg());  
      }    
      TimeStampResp response = tspHttpResponse.getTimeStampResp();
      return response;
    } catch (IOException ex) {
      throw new TspException("Error connecting to TSA: " + ex.toString());   
    } catch (CodingException ex) {
      throw new TspException("Error encoding tsp request: " + ex.getMessage());   
    }  
  }
  
  /**
   * Adds a SignatureTimeStampToken attribute to the given SignerInfo.
   *
   * @param tspToken the time stamp token to be added as attribute
   * @param signerInfo the SignerInfo to be time stamped
   * 
   * @exception TspException if some error occurs when adding the attribute
   */
  public static void timeStamp(TimeStampToken tspToken,
                               SignerInfo signerInfo)
    
    throws TspException {
    
    if (tspToken == null) {
      throw new NullPointerException("tspToken must not be null!");
    }
    if (signerInfo == null) {
      throw new NullPointerException("signerInfo must not be null!");
    }
    
    try {
      // include TimeStampToken as unsigned attribute  
      SignatureTimeStampToken stst = new SignatureTimeStampToken(tspToken.toASN1Object());
      signerInfo.addUnSignedAttribute(new Attribute(stst));
    } catch (CodingException ex) {
      throw new TspException("Error encoding TimeStampToken attribute: " + ex.getMessage()); 
    } catch (CMSException ex) {
      throw new TspException("Error adding SignatureTimeStampToken attribute: " + ex.getMessage());   
    }    
    
  } 
  
  /**
   * Validates the response received from the TSA.
   * 
   * @param response the time stamp response to be validated
   * @param request the time stamp request that has been sent
   *
   * @exception TspException if the response is invalid (wrong MessageImprint, missing certificate,...)
   */
  public static void validateResponse(TimeStampResp response,
                                      TimeStampReq request)
  
    throws TspException {
    
    // get the status info
    PKIStatusInfo statusInfo = response.getPKIStatusInfo();
    // status?
    PKIStatus status = statusInfo.getPKIStatus();
    int statusCode = status.getStatus();
    if ((statusCode != PKIStatus.GRANTED) && (statusCode != PKIStatus.GRANTED_WITH_MODS)) {
      PKIFailureInfo failureInfo = statusInfo.getPKIFailureInfo();
      throw new TspException("TSA reported failure:\n" + status + ((failureInfo == null) ? "" : ("\n("+failureInfo+")")));
    }    
    // we got a TimeStampToken
    TimeStampToken token = response.getTimeStampToken();
    if (token == null) {
      throw new TspException("Got invalid response from TSA: TimeStampToken is missing");  
    }
    // verify the signature of the token
    X509Certificate tsaCert = (X509Certificate)token.getSigningCertificate();
    if (tsaCert == null) {
      throw new TspException("Invalid response: does not contain the requested TSA certificate!");   
    }    
    token.verifyTimeStampToken(tsaCert);
    try {
      if (token.isSigningCertificate(tsaCert) == false) {
        throw new TspException("Certificate identified by SigningCertificate is not TSA cert!");
      }
    } catch (CertificateException e) {
      throw new TspException("Error checking SigningCertificate attribute: " + e.toString());
    }  
    
    // here we should validate the TSA certificate (omitted in this demo)    
    
    // get the TSTInfo
    TSTInfo tstInfo = token.getTSTInfo();
    // validate the MessageImprint
    MessageImprint mi = tstInfo.getMessageImprint();
    if (mi.equals(request.getMessageImprint()) == false) {
      throw new TspException("Response MessageImprint does not match to request imprint!");
    }    
    // nonce included?
    BigInteger requestNonce = request.getNonce();
    if (requestNonce != null) {
      BigInteger responseNonce = tstInfo.getNonce();
      if (responseNonce == null) {
        throw new TspException("Invalid Response! Does not contain nonce!"); 
      }  
      if (requestNonce.equals(responseNonce) == false) {
        throw new TspException("Response nonce does not match to request nonce!");
      }  
    }    
    // did we request a TSA policy
    ObjectID requestPolicy = request.getTSAPolicyID();
    if (requestPolicy != null) {
      if (requestPolicy.equals(tstInfo.getTSAPolicyID()) == false) {
        throw new TspException("TSA policy not trusted!");
      }  
    }    
  }  
  
  /**
   * Validates an unsigned SignatureTimeStampToken contained in the given
   * SignerInfo.
   *  
   * @param signerInfo the SignerInfo containing the SignatureTimeStampToken attribute
   * 
   * @exception TspException if the time stamp token validation fails
   * @exception NullPointerException if the SignerInfo does not contain a
   *                                  SignatureTimeStampToken as expected
   * 
   */
  public static void validateSignatureTimeStampToken(SignerInfo signerInfo) 
    throws TspException {
    
    SignatureTimeStampToken signatureTimeStampToken; 
    TimeStampToken token;
    try {
      signatureTimeStampToken = 
        (SignatureTimeStampToken)signerInfo.getUnsignedAttributeValue(SignatureTimeStampToken.oid);
      if (signatureTimeStampToken == null) {
        throw new NullPointerException("Missing SignatureTimeStampToken in SignerInfo!");
      }
      token = new TimeStampToken(signatureTimeStampToken.toASN1Object());
    } catch (CMSException ex) {
      throw new TspException("Error parsing time stamp token: " + ex.toString());
    } catch (CodingException ex) {
      throw new TspException("Error parsing time stamp token: " + ex.toString());
    }
    // verify the signature of the token (we assume that the TSA certificate is included)
    X509Certificate tsaCert = (X509Certificate)token.getSigningCertificate();
    if (tsaCert == null) {
      throw new TspException("Cannot verify TimeStampToken: TSA certificate not included!");   
    }    
    token.verifyTimeStampToken(tsaCert);
    
    // here we should validate the TSA certificate (omitted in this demo)    
  
    // get the TSTInfo
    TSTInfo tstInfo = token.getTSTInfo();     
      
    // we may check the MessageImprint to see if actually the signature value has been time stamped
    MessageImprint imprint = tstInfo.getMessageImprint();
    AlgorithmID hashAlg = imprint.getHashAlgorithm();
    MessageDigest md = null;
    try {
      md = hashAlg.getMessageDigestInstance();
    } catch (NoSuchAlgorithmException ex) {
      throw new TspException("Cannot calculate MessageImprint! Hash Algorithm not supported: " + ex.getMessage()); 
    } 
     
    // calculate a hash from the signature value
    byte[] toBeTimeStamped = md.digest(signerInfo.getSignatureValue());
    // and compare it against the MessageImprint value
    if (CryptoUtils.equalsBlock(toBeTimeStamped, imprint.getHashedMessage()) == false) {
      throw new TspException("Invalid timestamp token: wrong MessageImprint value!");
    }    
    
    System.out.println("Signature has been time stamped from " + tsaCert.getSubjectDN() + " at: " + tstInfo.getGenTime());
  }
  
  
  
    
}    