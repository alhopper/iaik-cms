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
// $Header: /IAIK-CMS/current/src/demo/smime/ess/MySecurityLabelHandler.java 4     24.08.07 16:39 Dbratko $
// $Revision: 4 $
//

package demo.smime.ess;

import iaik.asn1.ObjectID;
import iaik.cms.SignerInfo;
import iaik.smime.ess.ESSSecurityLabel;
import iaik.smime.ess.SecurityLabelException;
import iaik.smime.ess.utils.SecurityLabelHandler;

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

/**
 * Simple demo SecurityLabelHandler.
 * <p> 
 * This demo SecurityLabelHandler implements a simple security policy based on the
 * default security classifications "unmarked", "unclassified", "restricted", 
 * "confidential", "secret", "top-secret". Since the SignedData message created
 * by this {@link demo.smime.ess.SecurityLabelDemo demo} only contains an ESS 
 * {@link iaik.smime.ess.ESSSecurityLabel SecurityLabel} attribute with 
 * classification "confidential", only this classification is processed by
 * the {@link #processESSSecurityLabel processESSSecurityLabel} method of this
 * demo handler. "unmarked" and "unclassified" are handled as "not critical"
 * content (i.e. the content can be accessed by any one), "secret", "top-secret"
 * lock the content (i.e. it is not displayed), and "restricted" and 
 * "confidential" popup a confirmation dialog reminding the recipient about
 * the confidentiality of the message content.
 * 
 * @see demo.smime.ess.SecurityLabelDemo
 * @see iaik.smime.ess.ESSSecurityLabel
 * 
 * @author Dieter Bratko
 */
public class MySecurityLabelHandler implements SecurityLabelHandler {
    
  // our SecurityLabelHandler only checks for presence of one specific SecurityLabel policy
  public final static ObjectID MY_SECURITY_POLICY_ID = new ObjectID("1.3.6.1.4.1.2706.2.2.4.4.1", "My Security Policy"); 
  
  /**
   * Processes the given SecurityLabel attribute.
   * 
   * @param securityLabel the SecurityLabel attribute to be handled
   * @param signerInfos the SignerInfos of the SignedData message containing
   *                    the SecurityLabel attribute
   * 
   * @exception SecurityLabelException if the message content has to be locked because
   *                                   of the implemented security strategy
   */  
  public void processESSSecurityLabel(ESSSecurityLabel securityLabel, 
                                      SignerInfo[] signerInfos)
    throws SecurityLabelException {
    
    if (securityLabel != null) {
      if (securityLabel.getSecurityPolicyIdentifier().equals(MY_SECURITY_POLICY_ID)) {
        System.out.println("Processing SecurityLabel attribute ("+MY_SECURITY_POLICY_ID.getID()+")");
        // we only check the (default) security classification
        int classification = securityLabel.getSecurityClassification();
        System.out.println("Security Classification is " + classification +
                           " (" + securityLabel.getSecurityClassificationName() + ")");
        String essPrivacyMark = securityLabel.getPrivacyMarkString();
        if (essPrivacyMark != null) {
          System.out.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
          System.out.println(essPrivacyMark);
          System.out.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        }    
        switch (classification) {
          case ESSSecurityLabel.UNMARKED : 
          case ESSSecurityLabel.UNCLASSIFIED : 
            // do nothing, allow anyone to access the content
            break;
          case ESSSecurityLabel.RESTRICTED : 
          case ESSSecurityLabel.CONFIDENTIAL : 
            // display a dialog reminding that the contents is confidential
            
            StringBuffer message = new StringBuffer(256);
            String msg1 = essPrivacyMark;
         
            message.append("Please be aware  that this message contains high confidential data.\n");
            message.append("If  you  are  not  absolutly  sure  to be able to keep  the confidentiality\n");
            message.append("of the message you should NOT press the OK button and NOT view\n"); 
            message.append("the content of the message!\n");
            String question = "Continue to view the message content?";
       
            int selected = JOptionPane.showConfirmDialog(
              null ,
              getConfirmationPanel(msg1, message.toString(), question, 34),
              "IAIK-CMS Demo: Confidiantality Confirmation",
              JOptionPane.OK_CANCEL_OPTION,
              JOptionPane.WARNING_MESSAGE);
           
             if( selected != JOptionPane.OK_OPTION ) {
               throw new SecurityLabelException("Content access denied "+
                                                "(recipient cannot guarantee to keep the confidentiality of the message)!");
             }
             break;
          case ESSSecurityLabel.SECRET : 
          case ESSSecurityLabel.TOP_SECRET : 
            // here we may implement some interaction with the user to only allow
            // access to the content based on some user authentication (for
            // instance by using attribute certificates)
            // in this demo we only deny to access the content
            throw new SecurityLabelException("Content access denied (user authentication required)!");
          default : 
            // unknown classification: do not allow to access the content;
            throw new SecurityLabelException("Content access denied (unknown security classification)!");
        }    
      }  
    }    
    
  }      
  
  

  
  /**
   * Returns a JPanel consisting of one messages label, a text area and one 
   * confirmation query.
   * <p>
   *
   * @param msg the message
   * @param text the text to display
   * @param question the confirmation question
   * @param cols the number of columns for the text area
   * 
   * @return the JPanel consisting of message labels and text area
   */
  static JPanel getConfirmationPanel(String msg, String text, String question, int cols) {
    
    int gridy = 0;
    GridBagLayout gb = new GridBagLayout();
    GridBagConstraints gbc = new GridBagConstraints();
    gbc.anchor = GridBagConstraints.WEST;
    JLabel msgLabel1 = new JLabel(msg, JLabel.CENTER);
    gb.setConstraints(msgLabel1,gbc);
    gbc.gridy = ++gridy;
    gbc.insets = new Insets(10,0,0,0);
    JTextArea textField = new JTextArea();
    textField.setEditable(false);
    textField.setBackground(Color.lightGray);
    textField.setRows(5);
    textField.setColumns(cols);
    textField.append(text);
	  JScrollPane textPane = new JScrollPane();
    textPane.getViewport().add(textField);
  	gb.setConstraints(textPane,gbc);
    gbc.gridy = ++gridy;
	
    JLabel questionLabel = new JLabel(question, JLabel.CENTER);
    gb.setConstraints(questionLabel,gbc);
    JPanel confirmPanel = new JPanel(gb);
    confirmPanel.add(msgLabel1);
    confirmPanel.add(textPane);
    confirmPanel.add(questionLabel);
    return confirmPanel;
  }   
  
}    