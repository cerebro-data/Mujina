package mujina.idp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.util.Base64;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.util.XMLObjectHelper;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.util.XMLObjectHelper;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class TokenController {

  @Autowired
  private SAMLMessageHandler samlMessageHandler;

  protected final Logger LOG = LoggerFactory.getLogger(getClass());


  @GetMapping("/token.html")
  public String token(Authentication authentication, ModelMap modelMap)
      throws IOException, MarshallingException, MessageDecodingException,
      MetadataProviderException, SecurityException, SignatureException,
      TransformerConfigurationException, TransformerException, ValidationException {

    SAMLMessageContext messageContext = new SAMLMessageContext();
    //String assertionConsumerServiceURL = SsoController.getIDPAcsEndpoint() != null ? SsoController.getIDPAcsEndpoint() : authnRequest.getAssertionConsumerServiceURL();
    Response token = samlMessageHandler.buildSamlToken(authentication);
    modelMap.addAttribute("user", authentication);
    // Pretty print version of the token
    String formattedString = FormatRespose(token);
    modelMap.addAttribute("token", formattedString);
    // Version of the token appropriate for passing in an Authorization header
    modelMap.addAttribute("encodedToken", deflateAndEncodeTokenString(formattedString));
    return "token";
  }

  private String deflateAndEncodeTokenString(String formattedResponse) throws IOException {

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Deflater compresser = new Deflater(Deflater.BEST_COMPRESSION, true);
    DeflaterOutputStream dout = new DeflaterOutputStream(outputStream, compresser);
    dout.write(formattedResponse.getBytes("UTF-8"));
    dout.close();
    return new String(Base64.getEncoder().encode(outputStream.toByteArray()));
  }

  private String FormatRespose(final Response response)
      throws MarshallingException, TransformerConfigurationException,
      TransformerException {

    // Create a transformer to pretty print the XML
    StringWriter outputWriter = new StringWriter();
    Transformer transformer = TransformerFactory.newInstance().newTransformer();
    transformer.setOutputProperty(OutputKeys.INDENT, "yes");
    transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
    transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
    transformer.setOutputProperty(OutputKeys.METHOD, "xml");
    transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");

    transformer.transform(
        new DOMSource(XMLObjectHelper.marshall(response)), new StreamResult(outputWriter));
    return outputWriter.toString();
  }
}
