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
// $Header: /IAIK-CMS/current/src/demo/cms/tsp/TSPServer.java 10    5.09.07 15:10 Dbratko $
//

package demo.cms.tsp;

import iaik.asn1.DerCoder;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.tsp.PKIFailureInfo;
import iaik.tsp.PKIFreeText;
import iaik.tsp.PKIStatus;
import iaik.tsp.PKIStatusInfo;
import iaik.tsp.TSTInfo;
import iaik.tsp.TimeStampReq;
import iaik.tsp.TimeStampResp;
import iaik.tsp.TimeStampToken;
import iaik.tsp.TspSigningException;
import iaik.utils.LineInputStream;
import iaik.x509.X509Certificate;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.CharArrayReader;
import java.io.CharArrayWriter;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.PrivateKey;
import java.util.Date;
import java.util.StringTokenizer;

import demo.keystore.CMSKeyStore;

/**
 * A simple TSP server. Used by the {@link TimeStampDemo TimeStampDemo}.
 *
 * @see TimeStampDemo
 *
 * @version File Revision <!-- $$Revision: --> 10 <!-- $ -->
 * 
 * @author Dieter Bratko
 */
public class TSPServer {
  
  /**
   * Debug mode enabled?
   */
  private static PrintWriter debugWriter_;
  
  /**
   * Carriage Return Line Feed.
   */
  private static final String CRLF = "\r\n";
  
  /**
   * Default Port number.
   */ 
  private final static int DEFAULT_PORT = 3188;
  
  /**
   * TSA policy id.
   */                                                    
  public static final ObjectID TSA_POLICY_ID = new ObjectID("1.3.6.1.4.1.2706.2.2.5.2.1.1.1", "IAIK-CMS Demo TSA");
  
  /**
   * The private signing key of the tsp server.
   */
  private PrivateKey privateKey_;
  
  /**
   * The certificate chain of the tsp server.
   */
  private X509Certificate[] certChain_;
  
  /**
   * Algorithm to be used for signing the response.
   */ 
  private AlgorithmID signatureAlgorithm_;
  
  /**
   * Algorithm to be used for calculating the signature hash.
   */ 
  private AlgorithmID hashAlgorithm_;
  
  /**
   * Server socket.
   */
  private ServerSocket serverSocket_;
  
  /**
   * Port number.
   */
  private int port_;
  
  /**
   * Creates a TSP server for listening on time stamp
   * requests on port 3188.
   * Server key (for response signing) and certificate are
   * read from the IAIK-CMS demo test keystore ("cms.keystore")
   * which can be created by running the {@link demo.keystore.SetupCMSKeyStore
   * SetupCMSKeyStore} program.
   *
   */
  public TSPServer() {
    this(DEFAULT_PORT, 
         CMSKeyStore.getTspServerPrivateKey(),
         CMSKeyStore.getTspServerCertificate(),
         (AlgorithmID)AlgorithmID.sha1WithRSAEncryption.clone(),
         (AlgorithmID)AlgorithmID.sha1.clone());
    
    
    
  }
  
  /**
   * Creates a TSP server.
   *
   * @param port the port to listen on (default 3188)
   * @param privateKey the private key of the tsp server to be used for signing the tsp response
   * @param certChain the certificate chain of the server (to be included in the response, if requested)
   * @param signatureAlgorithm the algorithm used for signing the response
   * @param hashAlgorithm algorithm to be used for calculating the signature hash
   */ 
  public TSPServer(int port, 
                   PrivateKey privateKey,
                   X509Certificate[] certChain,
                   AlgorithmID signatureAlgorithm,
                   AlgorithmID hashAlgorithm) {
    
    if (privateKey == null) {
      throw new NullPointerException("Private key must not be null!");
    }
    if ((certChain == null) || (certChain.length == 0)) {
      throw new NullPointerException("Certificate chain must not be null!");
    }
    if (signatureAlgorithm == null) {
      throw new NullPointerException("Signature algorithm must not be null!");
    }
    if (hashAlgorithm == null) {
      throw new NullPointerException("Hash algorithm must not be null!");
    }
    port_ = (port < 0) ? DEFAULT_PORT : port;
    privateKey_ = privateKey;
    certChain_ = certChain;
    signatureAlgorithm_ = signatureAlgorithm;
    hashAlgorithm_ = hashAlgorithm;
  }

  /**
   * Starts the TSP Server.
   */
  public void start() {

    if (serverSocket_ == null) { 
      try {
        serverSocket_ = new ServerSocket(port_);
      } catch( IOException e ) {
        System.err.println("Error binding to port " + port_ + ":");
        e.printStackTrace();
        return;
      }
    }  
    debug(-1, "Listening for TSP request over HTTP on port " + port_ + "...");
    
    long id = 0;

    // a thread for each new Request
    while (true) {
      if (serverSocket_ != null) {
        try {
          Socket socket = serverSocket_.accept();
          TSPServerThread tspServerThread = new TSPServerThread(socket, 
                                                                privateKey_,
                                                                certChain_,
                                                                (AlgorithmID)signatureAlgorithm_.clone(),
                                                                hashAlgorithm_,
                                                                ++id); 
          tspServerThread.start();
        } catch( SocketException e ) {
          // ignore 
        } catch( IOException e ) {
          debug(-1, e);
        }
      } else {
        break;
      }
    }

  }
  
  /**
   * Stops the TSP Server.
   */
  public void stop() {
    if (serverSocket_ != null) {
      ServerSocket serverSocket = serverSocket_;
      serverSocket_ = null;
      try {
        serverSocket.close();
      } catch (Exception ex) {
        // ignore
      }
    }  
    serverSocket_ = null;
  }
  
  /**
   * Gets the port number the server is listening on.
   */
  public int getPort() {
    return port_;
  }
  
  /**
   * Handles one client request.
   */
  final static class TSPServerThread extends Thread {
    
    /**
     * The socket for talking with the client.
     */
    private Socket socket_;
    /**
     * The private signing key of the tsp server.
     */
    private PrivateKey privateKey_;
    
    /**
     * The certificate chain of the tsp server.
     */
    private X509Certificate[] certChain_;
    
    /**
     * Algorithm to be used for signing the response.
     */ 
    private AlgorithmID signatureAlgorithm_;
    
    /**
     * Algorithm to be used for calculating the signature hash.
     */ 
    private AlgorithmID hashAlgorithm_;
    
    /**
     * The id number of the thread.
     */
    private long id_;
    
    
    /**
     * Creates an TSP server thread for handling an TSPRequest.
     *
     * @param socket the socket from which to read the request and to which
     *                          to send the response
     * @param privateKey the private key of the tsp server to be used for signing the tsp response
     * @param certChain the certificate chain of the server (to be included in the response, if requested)
     * @param signatureAlgorithm the algorithm used for signing the response
     * @param hashAlgorithm the algorithm used for calculating the signature hash
     * @param id the id number of the thread
     */
    public TSPServerThread(Socket socket, 
                           PrivateKey privateKey,
                           X509Certificate[] certChain,
                           AlgorithmID signatureAlgorithm,
                           AlgorithmID hashAlgorithm,
                           long id) {
          
       super("TSPServerThread" + id);
       this.socket_ = socket;
       privateKey_ = privateKey;
       certChain_ = certChain;
       signatureAlgorithm_ = signatureAlgorithm;
       hashAlgorithm_ = hashAlgorithm;
       id_ = id;
    }

    /** 
     * Handles the client request.
     */
    public void run() {
      try {
        socket_.setSoTimeout(1000*30);          
       
        OutputStream os = socket_.getOutputStream();
        InputStream is = socket_.getInputStream();
        DataOutputStream out = new DataOutputStream(new BufferedOutputStream(os));
        LineInputStream in = new LineInputStream(new BufferedInputStream(is));
        
        String line;
        line = in.readLine();
        StringTokenizer token = new StringTokenizer(line, " ");
        String method = token.nextToken();
        debug(id_, "Received request from " + socket_.getInetAddress() + ":");
        debug(id_, line);
        boolean invalidRequest = false;
        // print header lines
        do {
          line = in.readLine();
          debug(id_, line);
          line = line.toLowerCase();
          if (line.startsWith("content-type") &&
             (line.indexOf("application/timestamp-query") == -1)) {
            invalidRequest = true;
          }    
        } while( (line != null) && (line.length() != 0) );

        // we only accept POST
        if (!method.equalsIgnoreCase("POST")) {
          debug(id_, "\nInvalid method: " + method + ". Only POST supported. Sending ERROR");
          out.writeBytes("HTTP/1.0 405 Method Not Allowed");
          out.writeBytes(CRLF);
          out.writeBytes("Content-Type: text/html");
          out.writeBytes(CRLF);
          out.writeBytes("Server: IAIK TSP Demoserver");
          out.writeBytes(CRLF);
          out.writeBytes(CRLF);
          out.writeBytes("<HTML>");
          out.writeBytes(CRLF);
          out.writeBytes("<HEAD><TITLE>IAIK-CMS TSP Demo Server</TITLE></HEAD>");
          out.writeBytes(CRLF);
          out.writeBytes("<BODY>");
          out.writeBytes(CRLF);
          out.writeBytes("<H1>405 Method Not Allowed.</H1>");
          out.writeBytes(CRLF);
          out.writeBytes("<P>Method " + method + " not supported.");
          out.writeBytes(CRLF);
          out.writeBytes("<HR>Generated by <A HREF=\"http://jce.iaik.tugraz.at/\">IAIK-CMS</A>.");
          out.writeBytes("</BODY>");
          out.writeBytes(CRLF);
          out.writeBytes("</HTML>");
          out.writeBytes(CRLF);
          out.flush();
          out.close();
          return;
        }
        if (invalidRequest) {
          debug(id_, "Invalid request content type. Sending ERROR.");
          out.writeBytes("HTTP/1.0 400 Invalid request");
          out.writeBytes(CRLF);
          out.writeBytes("Content-Type: text/html");
          out.writeBytes(CRLF);
          out.writeBytes("Server: IAIK TSP Demoserver");
          out.writeBytes(CRLF);
          out.writeBytes(CRLF);
          out.writeBytes("<HTML>");
          out.writeBytes(CRLF);
          out.writeBytes("<HEAD><TITLE>IAIK-CMS TSP Demo Server</TITLE></HEAD>");
          out.writeBytes(CRLF);
          out.writeBytes("<BODY>");
          out.writeBytes(CRLF);
          out.writeBytes("<H1>400 Invalid Request.</H1>");
          out.writeBytes(CRLF);
          out.writeBytes("<P>Invalid Request. Expected <code>application/timestamp-query</code>");
          out.writeBytes(CRLF);
          out.writeBytes("<HR>Generated by <A HREF=\"http://jce.iaik.tugraz.at/\">IAIK-CMS</A>.");
          out.writeBytes("</BODY>");
          out.writeBytes(CRLF);
          out.writeBytes("</HTML>");
          out.writeBytes(CRLF);
          out.flush();
          out.close();
          return;
        }  
        // parse the request received
        byte[] response = null;
        debug(id_, "Parse request...");
        TimeStampResp tspResponse = createResponse(in, 
                                                   privateKey_, 
                                                   certChain_,
                                                   signatureAlgorithm_, 
                                                   hashAlgorithm_,
                                                   id_); 
        response = tspResponse.getEncoded();
        // now create and send the response
        debug(id_, "Sending response...");
        out.writeBytes("HTTP/1.0 200 OK");
        out.writeBytes(CRLF);
        out.writeBytes("Content-Type: application/timestamp-reply");
        out.writeBytes(CRLF);
        out.writeBytes("Server: IAIK TSP Demoserver");
        out.writeBytes(CRLF);
        out.writeBytes("Content-Length: " + response.length);
        out.writeBytes(CRLF);
        out.writeBytes(CRLF);
        out.write(response);
        out.flush();
        out.close();
      } catch (IOException ex) {
        debug(id_, ex);
      } finally {
        try {
          socket_.close();
        } catch (IOException e) {
          // ignore
        }    
      }        
    }
  }
  
  /**
   * Creates a TimeStampResponse from the given data
   * 
   * @param in the input stream from which to read the time stamp request
   * @param privateKey the private signing key of the tsp server
   * @param certChain the certificate chain of the tsp server
   * @param signatureAlgorithm the algorithm to be used for signing
   * @param hashAlgorithm the algorithm to be used for signature hashing
   * @param id an id counter (used for serial number creation)
   * 
   * @return the time stamp response
   */
  private final static TimeStampResp createResponse(InputStream in,
                                                    PrivateKey privateKey,
                                                    X509Certificate[] certChain,
                                                    AlgorithmID signatureAlgorithm,
                                                    AlgorithmID hashAlgorithm,
                                                    long id) {
    
    TimeStampResp tspResponse = null;
    //  parse request
    TimeStampReq tspRequest = null;
    try {
      tspRequest = new TimeStampReq(DerCoder.decode(in));
      // specific TSA policy requested?
      ObjectID reqPolicy = tspRequest.getTSAPolicyID();
      if  ((reqPolicy != null) && (reqPolicy.equals(TSA_POLICY_ID) == false)) {
        String msg = "Requested policy " + reqPolicy.getID() + " not accepted.";
        PKIStatusInfo statusInfo = new PKIStatusInfo(new PKIStatus(PKIStatus.REJECTION));
        statusInfo.setPKIFailureInfo(new PKIFailureInfo(PKIFailureInfo.UNACCEPTED_POLICY));
        statusInfo.setPKIFreeText(new PKIFreeText(msg));
        tspResponse = new TimeStampResp(statusInfo);
      }
      
    } catch (Exception ex) {
      String msg = "Invalid time stamp request. ";
      debug(id, msg + ex.toString());
      debug(id, ex);
      PKIStatusInfo statusInfo = new PKIStatusInfo(new PKIStatus(PKIStatus.REJECTION));
      statusInfo.setPKIFailureInfo(new PKIFailureInfo(PKIFailureInfo.BAD_DATA_FORMAT));
      statusInfo.setPKIFreeText(new PKIFreeText(msg));
      tspResponse = new TimeStampResp(statusInfo);
    }

    if (tspResponse == null) {
      // request successfully parsed

      //create TSTInfo
      TSTInfo tstInfo = new TSTInfo();
      tstInfo.setGenTime(new Date());
      tstInfo.setMessageImprint(tspRequest.getMessageImprint());
      if (tspRequest.getNonce() != null) {
        tstInfo.setNonce(tspRequest.getNonce());
      }
      
      // for simplicity we calculate the serial number from current date
      // and a serial number counter. The value of a counter (id) is not kept
      // beyound the lifetime of the server (as it might have be done practice).
      long serialNumber = id + System.currentTimeMillis();
      tstInfo.setSerialNumber(BigInteger.valueOf(serialNumber));
      tstInfo.setTSAPolicyID(TSA_POLICY_ID);
  
      //create TimeStampToken
      TimeStampToken token = new TimeStampToken(tstInfo);
      if (tspRequest.getCertReq()) {
        token.setCertificates(certChain);
      }
      token.setSigningCertificate(certChain[0]);
  
      token.setHashAlgorithm(hashAlgorithm);
      token.setPrivateKey(privateKey);
  
      try {
        token.signTimeStampToken();
      } catch (TspSigningException ex) {
        String msg = "Error signing time stamp response. ";
        debug(id ,msg);
        debug(id , ex);
        PKIStatusInfo statusInfo = new PKIStatusInfo(new PKIStatus(PKIStatus.REJECTION));
        statusInfo.setPKIFailureInfo(new PKIFailureInfo(PKIFailureInfo.SYSTEM_FAILURE));
        tspResponse = new TimeStampResp(statusInfo);
      }
      
      if (tspResponse == null) {
        // successful response
        tspResponse = new TimeStampResp();
        tspResponse.setTimeStampToken(token);
  
        PKIStatus status = new PKIStatus(PKIStatus.GRANTED);
        PKIStatusInfo info = new PKIStatusInfo(status);
  
        tspResponse.setPKIStatusInfo(info);
      }  
    }
    
    return tspResponse;
  }
  
  /** 
   * Writes debug information to the debug stream.
   *
   * @param id an id to be printed in front of the message
   * @param msg the message to be printed
   */
  private final static void debug(long id, String msg) {
    if (debugWriter_ != null) {
      if (id < 0) {
        debugWriter_.println("tsp_debug: " + msg);
      } else {
        debugWriter_.println("tsp_debug(" + id + "): " + msg);
      }  
    }
  }

  /** 
   * Debugs an exception.
   *
   * @param id an id to be printed in front of the exception messages
   * @param e the exception to be debugged
   */
  private final static void debug(long id, Throwable e) {
    CharArrayWriter writer = new CharArrayWriter();
    PrintWriter pwriter = new PrintWriter(writer);
    e.printStackTrace(pwriter);
    pwriter.flush();
    char[] chars = writer.toCharArray();
    BufferedReader reader = new BufferedReader(new CharArrayReader(chars));
    try {
      while (true) {
        String line = reader.readLine();
        if (line == null) {
          break;
        }
        debug(id, line);
      }
    } catch (IOException ex) {
      // ignore
    }
  }

  

  /**
   * Sets a stream to which debugging information shall be printed.
   * 
   * @param os the stream to which to print debugging information
   *           or <code>null</code> if no debugging information shall
   *           be printed 
   */
  public static synchronized void setDebugStream(OutputStream os) {
    debugWriter_ = (os == null) ? null : new PrintWriter(os, true);
  }

  
  
}
