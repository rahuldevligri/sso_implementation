package Saml.ssoImplementation.com.service;

import lombok.extern.slf4j.Slf4j;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.zip.Deflater;

@Slf4j
@Service
public class SpInitiatedSsoService implements ISpInitiatedSsoService {

    @Autowired
    private SAMLPostFormGenerator samlPostFormGenerator;

    /**
     * Generate SAML Request.
     * @return SAML Request
     */
    @Override
    public String generateSAMLRequest() throws Exception {
        String entityId = "Zumply"; // Example Entity ID
        String acsUrl = "https://zumply.com/login/sso?id=x7b93e27-814c-4c59-80cb-d0d2db34e7ac"; // ACS URL
        String destinationUrl = "https://adfs.bluestarindia.com/adfs/ls/"; // Destination URL
        log.debug("Generating SAML Request with entityId: {}, ACS URL: {}, Destination URL: {}", entityId, acsUrl, destinationUrl);

        // Step 1: Create the AuthnRequest
        AuthnRequest authnRequest = createAuthnRequest(entityId, acsUrl, destinationUrl);

        // Step 2: Marshall the AuthnRequest to XML
        String samlRequestXml = marshallSAMLObject(authnRequest);
        log.debug("Generated SAML Request XML: {}", samlRequestXml);

        // Step 3: Compress the SAML request using DEFLATE
        byte[] compressedSAMLRequest = compressWithDeflate(samlRequestXml);

        // Step 4: Base64 encode the compressed SAML request
        String base64EncodedSAML = Base64.getEncoder().encodeToString(compressedSAMLRequest);
        log.debug("Base64 Encoded SAML Request: {}", base64EncodedSAML);

        // Step 5: URL encode the Base64-encoded SAML request
        String urlEncodedSAML = URLEncoder.encode(base64EncodedSAML, StandardCharsets.UTF_8);
        log.debug("URL Encoded Base64 SAML Request: {}", urlEncodedSAML);

        // Step 6: Include the URL-encoded SAML request in the destination URL
        String redirectUrlWithSAML = destinationUrl + "?SAMLRequest=" + urlEncodedSAML;
        log.debug("Redirect URL with SAMLRequest: {}", redirectUrlWithSAML);

        // Step 7: Prepare the fields for the POST form
        Map<String, String> fields = new HashMap<>();
        fields.put("SAMLRequest", redirectUrlWithSAML);
        return samlPostFormGenerator.buildSAMLPostForm(redirectUrlWithSAML, fields);
    }

    /**
     * Create an AuthnRequest object.
     * @param entityId       The Entity ID of the SP
     * @param acsUrl         The Assertion Consumer Service URL
     * @param destinationUrl The Destination URL
     * @return AuthnRequest object
     */
    private AuthnRequest createAuthnRequest(final String entityId, final String acsUrl, final String destinationUrl) {
        XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

        log.debug("Creating AuthnRequest for entityId: {}", entityId);

        // Build the AuthnRequest object using QName
        AuthnRequest authnRequest = (AuthnRequest) Objects.requireNonNull(builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME))
                .buildObject(AuthnRequest.DEFAULT_ELEMENT_NAME);

        // Generate and log the ID
        String generatedId = "_" + UUID.randomUUID().toString();
        log.debug("Generated SAML Request ID: {}", generatedId);

        authnRequest.setID(generatedId);
        authnRequest.setVersion(SAMLVersion.VERSION_20);
        authnRequest.setIssueInstant(Instant.now());
        authnRequest.setDestination(destinationUrl);
        authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        authnRequest.setAssertionConsumerServiceURL(acsUrl);
        authnRequest.setForceAuthn(false);
        authnRequest.setIsPassive(false);
        authnRequest.setProviderName("Zumply");

        // Create Issuer
        Issuer issuer = (Issuer) Objects.requireNonNull(builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME)).buildObject(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue(entityId); // Set EntityId
        authnRequest.setIssuer(issuer);

        // Create NameIDPolicy
        NameIDPolicy nameIDPolicy = (NameIDPolicy) Objects.requireNonNull(builderFactory.getBuilder(NameIDPolicy.DEFAULT_ELEMENT_NAME))
                .buildObject(NameIDPolicy.DEFAULT_ELEMENT_NAME);
        nameIDPolicy.setAllowCreate(true);
        nameIDPolicy.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        authnRequest.setNameIDPolicy(nameIDPolicy);

        return authnRequest;
    }

    /**
     * Marshall the SAML object into XML.
     * @param authnRequest The AuthnRequest object
     * @return The marshalled SAML object as XML
     */
    private String marshallSAMLObject(final AuthnRequest authnRequest) throws Exception {
        // Marshall the object into XML
        Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(authnRequest);
        assert marshaller != null;
        Element element = marshaller.marshall(authnRequest);

        // Convert XML element to String
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes"); // Omit the XML declaration
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");

        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(element), new StreamResult(writer));

        String samlXml = writer.toString();
        log.debug("Marshalled SAML Request XML: {}", samlXml);

        return samlXml;
    }

    /**
     * Compress the input data using DEFLATE.
     * @param data The input data to compress
     * @return The compressed data
     */
    private byte[] compressWithDeflate(final String data) throws Exception {
        // Convert the input string to bytes
        byte[] input = data.getBytes(StandardCharsets.UTF_8);

        // Set up a Deflater for compression
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true); // true enables nowrap for raw DEFLATE
        deflater.setInput(input);
        deflater.finish();

        // Create a buffer to hold compressed data
        byte[] output = new byte[input.length];
        int compressedDataLength = deflater.deflate(output);
        deflater.end();

        // Return the exact length of compressed data
        byte[] compressedData = new byte[compressedDataLength];
        System.arraycopy(output, 0, compressedData, 0, compressedDataLength);

        return compressedData;
    }
}

