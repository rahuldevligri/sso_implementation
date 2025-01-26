package Saml.ssoImplementation.com.service;

import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.core.impl.*;
import org.opensaml.saml.saml2.metadata.EmailAddress;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.impl.KeyInfoBuilder;
import org.opensaml.xmlsec.signature.impl.SignatureBuilder;
import org.opensaml.xmlsec.signature.impl.X509CertificateBuilder;
import org.opensaml.xmlsec.signature.impl.X509DataBuilder;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.Signer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Collectors;

import static Saml.ssoImplementation.com.constant.Constant.PRIVATE_KEY;
import static Saml.ssoImplementation.com.constant.Constant.PUBLIC_CERTIFICATE;

@Service
public class SamlService implements ISamlService {

    @Autowired
    private SAMLPostFormGenerator samlPostFormGenerator;

    /**
     * Generates a SAML assertion and builds an HTML form to submit it to the SP.
     * @return samlResponse submit form
     * @throws Exception
     */
    @Override
    public String generateSamlAssertion(final String email) throws Exception {
        String redirectUrl = "https://zumply.com/authenticate/saml";
        String spUniqueId ="m82345mn";

        // PrivateKey
        PrivateKey privateKey = getPrivateKey();

        // X509Certificate
        X509Certificate certificate = getCertificate();

        // Step 1: Create and sign the SAML Assertion
        Assertion assertion = createAssertion(email);
        signAssertion(assertion, privateKey, certificate);

        // Step 2: Create SAML Response
        Response samlResponse = createSamlResponse(assertion);

        // Step 3: Validate the signature
        boolean isSignatureValid = validateSignature(samlResponse, certificate);
        if (!isSignatureValid) {
            throw new Exception("Signature validation failed for the generated SAML assertion.");
        }

        // Step 4: Serialize the Assertion
        String serializedAssertion = serializeAssertion(samlResponse);

        // Step 5: Base64Encode SAML Assertion
        String base64EncodedSAML = Base64.getEncoder().encodeToString(serializedAssertion.getBytes(StandardCharsets.UTF_8));

        // Step 5: Prepare the fields for the POST form
        Map<String, String> fields = new HashMap<>();
        fields.put("Id", spUniqueId);
        fields.put("EncryptedSaml", base64EncodedSAML);

        // Step 6: Build & return an HTML form with the SAML response
        return samlPostFormGenerator.buildSAMLPostForm(redirectUrl, fields);
    }


    /**
     * Loads the private key from a PEM file.
     * @return the PrivateKey instance
     */
    private PrivateKey getPrivateKey() throws Exception {
        // Clean the PEM format (remove headers and footers)
        String privateKey = PRIVATE_KEY;
        String privateKeyContent = privateKey
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .trim();

        // Remove any newlines or extra spaces
        privateKeyContent = privateKeyContent.replaceAll("\\s+", "");

        // Ensure Base64 padding is correct
        int padding = privateKeyContent.length() % 4;
        if (padding > 0) {
            privateKeyContent += "=".repeat(4 - padding); // Add missing '=' padding
        }

        // Decode the Base64 encoded string
        byte[] encoded = Base64.getDecoder().decode(privateKeyContent);

        // Convert the byte array into a PrivateKey object
        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // Use "RSA" or the appropriate algorithm
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encoded));
    }

    /**
     * Loads the X509 certificate from a PEM file.
     * @return the X509Certificate instance
     */
    private X509Certificate getCertificate() throws Exception {
        // Clean the PEM format (remove headers, footers, and any extra spaces/newlines)
        String signingCert = PUBLIC_CERTIFICATE;
        String certificateContent = signingCert
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", ""); // Remove any extra spaces or newlines

        // Decode the Base64 encoded string
        byte[] encoded = Base64.getDecoder().decode(certificateContent);

        // Create a CertificateFactory for X.509 certificates
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        // Generate the X509Certificate from the byte array
        return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(encoded));
    }

    /**
     * Creates a SAML assertion with the given email address.
     * @param email the email address
     * @return the Assertion object
     */
    private Assertion createAssertion(String email) {
        Assertion assertion = new AssertionBuilder().buildObject();
        assertion.setID(String.valueOf(UUID.randomUUID()));
        assertion.setIssueInstant(Instant.now());

        // Issuer -IDP
        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setValue("Zumply"); //IDP Entity ID as Issuer
        assertion.setIssuer(issuer);

        // Subject - SP identify user
        Subject subject = new SubjectBuilder().buildObject();
        NameID nameID = new NameIDBuilder().buildObject();
        nameID.setValue(email);
        nameID.setFormat(NameID.EMAIL);
        subject.setNameID(nameID);

        // Subject Confirmation
        SubjectConfirmation confirmation = new SubjectConfirmationBuilder().buildObject();
        confirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
        SubjectConfirmationData confirmationData = new SubjectConfirmationDataBuilder().buildObject();
        confirmationData.setNotOnOrAfter(Instant.now().plusSeconds(3600)); // Valid for 1 hour
        confirmationData.setRecipient("https://zumply.com/authenticate/saml"); // Reply ACS URL
        confirmation.setSubjectConfirmationData(confirmationData);
        subject.getSubjectConfirmations().add(confirmation);
        assertion.setSubject(subject);

        // Conditions
        Conditions conditions = new ConditionsBuilder().buildObject();
        conditions.setNotBefore(Instant.now());
        conditions.setNotOnOrAfter(Instant.now().plusSeconds(3600)); // Valid for 1 hour

        AudienceRestriction audienceRestriction = new AudienceRestrictionBuilder().buildObject();
        Audience audience = new AudienceBuilder().buildObject();
        audience.setURI("https://client.zumply.com/saml2/"); // SP Entity ID as audience
        audienceRestriction.getAudiences().add(audience);
        conditions.getAudienceRestrictions().add(audienceRestriction);
        assertion.setConditions(conditions);

        // Authentication Statement
        AuthnStatement authnStatement = new AuthnStatementBuilder().buildObject();
        authnStatement.setAuthnInstant(Instant.now());

        AuthnContext authnContext = new AuthnContextBuilder().buildObject();
        AuthnContextClassRef authnContextClassRef = new AuthnContextClassRefBuilder().buildObject();
        authnContextClassRef.setURI(AuthnContext.PASSWORD_AUTHN_CTX);
        authnContext.setAuthnContextClassRef(authnContextClassRef);
        authnStatement.setAuthnContext(authnContext);
        assertion.getAuthnStatements().add(authnStatement);

        // AttributeStatement
        AttributeStatement attributeStatement = new AttributeStatementBuilder().buildObject();
        Attribute attribute = new AttributeBuilder().buildObject();
        attribute.setName(EmailAddress.DEFAULT_ELEMENT_LOCAL_NAME);  // Attribute name

        // AttributeValue to the Attribute
        XSString attributeValue = (XSString) XMLObjectSupport.buildXMLObject(XSString.TYPE_NAME);
        attributeValue.setValue(email);
        attribute.getAttributeValues().add(attributeValue);
        attributeStatement.getAttributes().add(attribute);
        assertion.getAttributeStatements().add(attributeStatement);

        return assertion;
    }

    /**
     * Signs the SAML assertion using the private key and certificate.
     * @param assertion the Assertion object
     * @param privateKey the private key
     * @param certificate the X509 certificate
     * @throws Exception
     */
    private void signAssertion(final Assertion assertion, final PrivateKey privateKey, final X509Certificate certificate) throws Exception {
        // Create a signing credential
        BasicX509Credential signingCredential = new BasicX509Credential(certificate, privateKey);

        // Build the signature
        Signature signature = new SignatureBuilder().buildObject();
        signature.setSigningCredential(signingCredential);
        signature.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        signature.setCanonicalizationAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#");

        // Create KeyInfo with X509Data containing the certificate
        KeyInfo keyInfo = new KeyInfoBuilder().buildObject();
        X509Data x509Data = new X509DataBuilder().buildObject();

        // OpenSAML X509Certificate object
        org.opensaml.xmlsec.signature.X509Certificate x509CertElement = new X509CertificateBuilder().buildObject();

        // Set the Base64-encoded certificate value
        String encodedCertificate = Base64.getEncoder().encodeToString(certificate.getEncoded());
        x509CertElement.setValue(encodedCertificate); // This will now work since OpenSAML has this method

        // Add the certificate to X509Data
        x509Data.getX509Certificates().add(x509CertElement);
        keyInfo.getX509Datas().add(x509Data);

        // Set the KeyInfo to the signature
        signature.setKeyInfo(keyInfo);

        // Set the signature on the assertion
        assertion.setSignature(signature);

        // Marshal and sign
        Marshaller marshaller = XMLObjectSupport.getMarshaller(assertion);
        if (marshaller == null) {
            throw new MarshallingException("No marshaller found for assertion");
        }
        marshaller.marshall(assertion);

        // Sign the object
        Signer.signObject(signature);
    }

    /**
     * Creates a SAML response containing the signed assertion.
     * @param assertion the signed assertion
     * @return the Response object
     */
    private Response createSamlResponse(final Assertion assertion) {
        Response response = new ResponseBuilder().buildObject();
        response.setID(UUID.randomUUID().toString());
        response.setIssueInstant(Instant.now());
        response.setDestination("https://zumply.com/authenticate/saml");
        response.setVersion(SAMLVersion.VERSION_20);
        // Issuer
        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setFormat(NameIDType.ENTITY);
        issuer.setValue("Zumply");
        response.setIssuer(issuer);
        // Status
        Status status = new StatusBuilder().buildObject();
        StatusCode statusCode = new StatusCodeBuilder().buildObject();
        statusCode.setValue(StatusCode.SUCCESS);
        status.setStatusCode(statusCode);
        response.setStatus(status);
        // Add the signed assertion to the response
        response.getAssertions().add(assertion);

        return response;
    }

    /**
     * Validates the signature of the SAML response.
     * @param samlResponse the SAML response
     * @param certificate the X509 certificate
     * @return true if the signature is valid, false otherwise
     * @throws Exception
     */
    public boolean validateSignature(Response samlResponse, X509Certificate certificate) throws Exception {
        // Extract the assertion from the response
        Assertion assertion = samlResponse.getAssertions().get(0);

        // Validate the signature
        Signature signature = assertion.getSignature();
        if (signature == null) {
            throw new Exception("No signature found on the SAML assertion.");
        }

        // Build a credential using the certificate
        X509Credential credential = new BasicX509Credential(certificate);

        try {
            // Validate the signature
            SignatureValidator.validate(signature, credential);
            return true; // Signature is valid
        } catch (SignatureException e) {
            System.err.println("Signature validation failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Serializes the SAML assertion to a string.
     * @param assertion the assertion object
     * @return the serialized assertion
     * @throws Exception
     */
    private String serializeAssertion(final Response assertion) throws Exception {
        Marshaller marshaller = XMLObjectSupport.getMarshaller(assertion);
        if (marshaller == null) {
            throw new MarshallingException("No marshaller found for assertion");
        }
        org.w3c.dom.Element element = marshaller.marshall(assertion);

        // Convert to string
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(element), new StreamResult(writer));
        return writer.toString();
    }
}
