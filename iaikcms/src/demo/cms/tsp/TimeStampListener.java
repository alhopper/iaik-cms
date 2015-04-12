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
// $Header: /IAIK-CMS/current/src/demo/cms/tsp/TimeStampListener.java 15    24.08.07 16:39 Dbratko $
// $Revision: 15 $
//

package demo.cms.tsp; 

import iaik.asn1.ObjectID;
import iaik.cms.CMSException;
import iaik.cms.SDSEncodeListener;
import iaik.cms.SignedDataStream;
import iaik.cms.SignerInfo;
import iaik.tsp.TimeStampReq;
import iaik.tsp.TimeStampResp;
import iaik.tsp.TspException;

import java.io.OutputStream;
import java.io.PrintWriter;
import java.security.SignatureException;

/**
 * A simple SignedDataStream encode listener implementation allowing an
 * application to add a SignatureTimeStampToken attribute to the SignerInfo
 * of a SignedDataStream (during the encoding is performed).
 * <p>
 * Using an SignedDataStream encode listener for adding a SignatureTimeStampToken may
 * be useful when having to time stamp the signature calculated from a large data
 * volume. Since reading all the data into memory may cause an OutOfMemory problem, 
 * class {@link iaik.cms.SignedDataStream SignedDataStream} should to be used for
 * creating/encoding the SignedData object and the SignatureTimeStampToken may be 
 * added by means of a {@link iaik.cms.SDSEncodeListener SDSEncodeListener}.
 * <p>
 * This SDSEncodeListener implements method {@link #afterComputeSignature(SignedDataStream)
 * afterComputeSignature} to add a SignatureTimeStampToken attribute to the SignerInfo of a
 * SignedDataStream object (<i>Attention</i>: This demo assumes that the SignedData contains
 * only one single SignerInfo). When {@link #TimeStampListener(String) creating} a TimeStampListener
 * the HTTP URL of the Time Stamp Authority from which to get the TimeStamp has to be
 * supplied (<i>Attention</i>: This demo only works for TSAs that can be accessed via http).
 * This SDSEncodeListener implements method {@link #afterComputeSignature afterComputeSignature}
 * to connect to the specified TSA service to get a timestamp for the signature value
 * of the single SignerInfo object. The TimeStampToken received from the TSA then is
 * included as unsigned {@link iaik.smime.attributes.SignatureTimeStampToken SignatureTimeStampToken}
 * attribute into the SignerInfo object. If there occurs an error during the TSP processing
 * an exception is thrown, except the application has decided to {@link #setStopOnTSPProcessingError
 * finsih} the SignedData creating/encoding procedure without including the SignatureTimeStampToken
 * attribute (which then may be added later).
 * <p>
 * This SDSEncodeListener implementation is part of the CMS TimeStamp demo.
 * Please look at {@link demo.cms.tsp.TimeStampDemo TimeStampDemo} for an usage example:
 * <pre>
 * // cretae a SignedDataStream object
 * SignedDataStream signedData = ...;
 * ...
 * // add certificates and SignerInfo...
 * ...
 * // create and add a TimeStampListener to include a TimeStampToken to be obtained from the specified TSA
 * String tsaUrl = "http://...";
 * TimeStampListener tsl = new TimeStampListener(tsaUrl);
 * // debug info goes to System.out
 * tsl.setDebugStream(System.out);
 * signedData.setSDSEncodeListener(tsl);   
 * ...
 * // encode the SignedData to some output stream
 * OutputStream os = ...;
 * signedData.writeTo(...);
 * </pre>
 * 
 * 
 * @see demo.cms.tsp.TimeStampDemo
 * @see iaik.cms.SDSEncodeListener
 * @see iaik.cms.SignedDataStream
 * @see iaik.cms.SignerInfo
 * @see iaik.smime.attributes.SignatureTimeStampToken
 * 
 * @author Dieter Bratko
 */
public class TimeStampListener extends SDSEncodeListener {
  /**
   * The URL of the TimeStamp Responder to which to connect to.
   */
  private String tsaUrl_;
  
  /**
   * The TimeStamp request (to be created and sent).
   */
  private TimeStampReq request_;
  
  /** 
   * The TimeStamp response (received from the TSA).
   */
  private TimeStampResp response_;
  
  /**
   * The TSA policy ID, if requested.
   */
  private ObjectID tsaPolicyID_;
  
  /**
   * Finish SignedData creation and do not include TimeStampToken attribute
   * if TSA response is invalid?
   */
  private boolean stopOnTSPProcessingError_;
  
  /**
   * Exception indicating an error during TSP processing.
   */
  private TspException tspFailure_;
  
  /** 
   * Writer to which debug information may be written.
   */
  private PrintWriter debugWriter_; 
   
  /**
   * Creates a TimeStampListener for the given TSA url.
   * 
   * @param tsaUrl the URL of the TimeStamp responder to which to connect to
   */
  public TimeStampListener(String tsaUrl) {
    if (tsaUrl == null) {
      throw new NullPointerException("TSA URL must not be null!");   
    }    
    tsaUrl_ = tsaUrl;    
    stopOnTSPProcessingError_ = true;
  }  
  
  /**
   * Decides whether SignedData creation shall be stopped and an exception shall
   * be thrown if the TSA response is invalid, or if the SignedData should be 
   * finished without including a SignatureTimeStampToken attribute (which then
   * may be added later).
   *
   * @param stop whether to stop processing if the TSA response is invalid or 
   *             to continue without including a TimeStampToken attribute
   */
  public void setStopOnTSPProcessingError(boolean stop) {
    stopOnTSPProcessingError_ = stop;
  }  
  
  /**
   * Sets the policyID of the TSA (if only some specific TSA (policy) shall be trusted).
   * If the TSA policy ID is set by this method, it will be included in the TimeStamp request
   * to indicate the TSA policy to be trusted. If the TSA sends back a different policy id in
   * the response, the response will be rejected.
   *
   * @param tsaPolicyID the TSA policy id to be trusted
   */
  public void setTSAPolicyID(ObjectID tsaPolicyID) {
    tsaPolicyID_ = tsaPolicyID; 
  }  
  
  /**
   * Sets the (already validated) TimeStamp response.
   * If the response is set by this method its inherent TimeStampToken will be
   * included as SignedData attribute. It no response is set, a TimeStamp
   * request is created and sent to the TSA that has been specified when
   * creating this TimeStampListener. The TimeStampToken of the response received
   * from the TSA then is included as attribute into the SignedData message.
   *
   * @param response the (already validated) TimeStampResponse containing the
   *                 TimeStampToken to be included as attribute into the SignedData message
   */
  public void setTimeStampResponse(TimeStampResp response) {
    response_ = response; 
  }  
  
  /**
   * Gets the TimeStampResponse.
   * After SignedDataStream.writeTo is finished, this method may be used to get the TimeStamp response received
   * from the TSA.
   *
   * @return the TimeStampResponse
   */
  public TimeStampResp getTimeStampResponse() {
    return response_; 
  }  
  
  /**
   * Gets the TimeStampRequest.
   * After SignedDataStream.writeTo is finished, this method may be used to get the TimeStamp request that
   * has been created and sent to the TSA.
   *
   * @return the TimeStampRequest
   */
  public TimeStampReq getTimeStampRequest() {
    return request_; 
  }  
  
  /**
   * Returns a TspException, if has been thrown during TSP processing.
   * If you have decided to {@link #setStopOnTSPProcessingError finish} the SignedData
   * encoding (and not include a TimeStamp attribute) if an TSP processing error has
   * been occured, you may use this method to query if the TSP processing has been completed
   * successfully or not.
   *
   * @return an TspException indicating an error during TSP processing, or <code>null</code>
   *         if the TSP processing has completed successfully
   */
  public TspException getTspFailure() {
    return tspFailure_; 
  }  
    
  /**
   * Does nothing.
   */
  protected void beforeComputeSignature(SignedDataStream signedData) 
    throws CMSException {
  }      
  
  /**
   * 
   * 
   * @param signedData the SignedDataStream to which to add a SignatureTimeStampToken
   * @exception CMSException if the SignatureTimeStampToken cannot be added (e.g. because
   *            the SignerInfo to which to add the SignatureTimeStampToken cannot be
   *            verified, or an error occurs when connecting to the TSA, or parsing/verifying
   *            the response)
   */
  protected void afterComputeSignature(SignedDataStream signedData) 
    throws CMSException {
     
    // counter sign any SignerInfo included
    SignerInfo signerInfo = signedData.getSignerInfos()[0];  
    try {
      // verify the signed data using the SignerInfo at index i
      debug("Verify SignerInfo signature.");
      signedData.verify(0);
      debug("Signature ok.");
      // create time stamp request
      if (response_ == null) {
        debug("Create time stamp request.");
        request_ = TSPDemoUtils.createRequest(signerInfo, tsaPolicyID_);
        debug("Send time stamp request to " + tsaUrl_);
        response_ = TSPDemoUtils.sendRequest(request_, tsaUrl_);
        // validate the response
        debug("Validate response.");
        TSPDemoUtils.validateResponse(response_, request_);
        debug("Response ok.");
      }  
      // time stamp
      debug("Add time stamp to SignerInfo.");
      TSPDemoUtils.timeStamp(response_.getTimeStampToken(), signerInfo);
    } catch (SignatureException ex) {
      // if the signature is not OK a SignatureException is thrown
      throw new CMSException("Signature verification ERROR for signer: "+ signerInfo.getSignerIdentifier()+
                              ex.getMessage());
    } catch (TspException ex) {
      tspFailure_ = ex;
      if (stopOnTSPProcessingError_) {
        throw new CMSException("Error getting timestamp for signer: " + signerInfo.getSignerIdentifier() +
                               "\n" + ex.toString());
      }                        
    } 
  }   
  
  /**
   * Sets the stream to which debug information shall be printed.
   *
   * @param out the stream to which debug information shall be written;
   *               maybe <code>null</code> for disabling debug output
   */
  public void setDebugStream(OutputStream out) {
    if (out == null) {
      debugWriter_ = null;
    } else {
      debugWriter_ = new PrintWriter(out, true);
    }
  }
  
  /** 
   * Prints the given debug message.
   *
   * @param msg the debug message to be printed.
   */
  private void debug(String msg) {
    if (debugWriter_ != null) {
      debugWriter_.println(msg);
    }  
  }
    
}    