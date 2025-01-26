package Saml.ssoImplementation.com.service;

import Saml.ssoImplementation.com.constant.Constant;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.opensaml.saml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml.saml2.core.impl.AudienceBuilder;
import org.opensaml.saml.saml2.core.impl.AudienceRestrictionBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml.saml2.core.impl.AttributeBuilder;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.impl.KeyInfoBuilder;
import org.opensaml.xmlsec.signature.impl.SignatureBuilder;
import org.opensaml.xmlsec.signature.impl.X509CertificateBuilder;
import org.opensaml.xmlsec.signature.impl.X509DataBuilder;
import org.opensaml.xmlsec.signature.support.Signer;
import org.springframework.stereotype.Service;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.FileNotFoundException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Scanner;
import java.util.UUID;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@Service
public class SamlSsoService implements ISamlSsoService {

    /**
     *
     * @return
     * @throws Exception
     */
    @Override
    public String generateSamlAssertion(final String sp) throws Exception {
        //sp redirect url
        String redirecturl = "https://zumply.com/authenticate/saml";

        //PrivateKey
        PrivateKey privateKey = getPrivateKey();

        //X509Certificate
        X509Certificate certificate = getCertificate();

        // Step:2 Create and sign the SAML Assertion
        Assertion assertion = createAssertion();
        signAssertion(assertion, privateKey, certificate);

        // Step 3: Serialize the Assertion
        String serializedAssertion = serializeAssertion(assertion);
        System.out.println("Saml Assertion: "+serializedAssertion);

        // Step 4: Encrypt the SAML Assertion
        String encryptedXMLContent = encryptSamlAssertion(serializedAssertion, privateKey);
        System.out.println("Encrypted Saml Assertion: "+encryptedXMLContent);

        // Step 5: Decrypt the SAML Assertion (Verification Step)
        String decryptedAssertion = decryptSamlAssertion(encryptedXMLContent, certificate.getPublicKey());
        System.out.println("Decrypted Saml Assertion: "+decryptedAssertion);

        String base64EncodedSAML =  Base64.getEncoder().encodeToString(encryptedXMLContent.getBytes(StandardCharsets.UTF_8));

        //Build an HTML form with the SAML response
        String htmlForm = buildSAMLPostForm(redirecturl, base64EncodedSAML);
        return htmlForm;
    }

    /**
     * Loads the private key from a PEM file.
     * @return the PrivateKey instance
     */
    private PrivateKey getPrivateKey() throws Exception {

        String privateKey = Constant.PRIVATE_KEY;

        // Clean the PEM format (remove headers, footers, and any extra spaces/newlines)
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
        String signingCert = Constant.PUBLIC_CERTIFICATE;
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


    private Assertion createAssertion() {
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
        nameID.setValue("rahuldevligri@gmail.com");
        nameID.setFormat(NameID.EMAIL);
        subject.setNameID(nameID);

        // Subject Confirmation
        SubjectConfirmation confirmation = new SubjectConfirmationBuilder().buildObject();
        confirmation.setMethod(SubjectConfirmation.METHOD_BEARER);

        SubjectConfirmationData confirmationData = new SubjectConfirmationDataBuilder().buildObject();
        confirmationData.setNotOnOrAfter(Instant.now().plusSeconds(3600)); // Valid for 1 hour
        confirmationData.setRecipient("https://zumply.client.com/saml2/Acs"); // Reply URL
        confirmation.setSubjectConfirmationData(confirmationData);

        subject.getSubjectConfirmations().add(confirmation);
        assertion.setSubject(subject);

        // Conditions
        Conditions conditions = new ConditionsBuilder().buildObject();
        conditions.setNotBefore(Instant.now());
        conditions.setNotOnOrAfter(Instant.now().plusSeconds(3600)); // Valid for 1 hour

        AudienceRestriction audienceRestriction = new AudienceRestrictionBuilder().buildObject();
        Audience audience = new AudienceBuilder().buildObject();
        audience.setURI("https://zumply.client.com/saml2/"); // SP Entity ID as audience
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
        attribute.setName("emailAddress");  // Attribute name

        // AttributeValue to the Attribute
        XSString attributeValue = (XSString) XMLObjectSupport.buildXMLObject(XSString.TYPE_NAME);
        attributeValue.setValue("rahuldevligri@gmail.com");  // User email value
        attribute.getAttributeValues().add(attributeValue);

        attributeStatement.getAttributes().add(attribute);
        assertion.getAttributeStatements().add(attributeStatement);

        return assertion;
    }

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

    private String serializeAssertion(final Assertion assertion) throws Exception {
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

    private String encryptSamlAssertion(final String serializedAssertion, final PrivateKey privateKey) throws Exception {
        // Step 1: Generate AES Symmetric Key
        SecretKey aesKey = generateAESKey();

        // Step 2: Encrypt the Serialized Assertion using AES
        byte[] encryptedAssertion = encryptWithAES(serializedAssertion, aesKey);

        // Step 3: Encrypt AES Key using RSA and X509Certificate private key
        byte[] encryptedAESKey = encryptAESKeyWithRSA(aesKey, privateKey);

        // Step 4: Load XML Template
        String xmlTemplate = loadXmlTemplate();
        String xmlContent = xmlTemplate
                .replace("{EncryptedAESKey}", Base64.getEncoder().encodeToString(encryptedAESKey))
                .replace("{EncryptedAssertion}", Base64.getEncoder().encodeToString(encryptedAssertion));
        return xmlContent;
    }
    private SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256); // AES-256
        return keyGenerator.generateKey();
    }

    private byte[] encryptWithAES(final String serializedAssertion, final SecretKey aesKey) throws Exception {
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // AES with PKCS5Padding
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        return aesCipher.doFinal(serializedAssertion.getBytes(StandardCharsets.UTF_8));
    }

    private byte[] encryptAESKeyWithRSA(final SecretKey aesKey, final PrivateKey privateKey) throws Exception {
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, privateKey);

        // Encrypt the AES key using RSA
        return rsaCipher.doFinal(aesKey.getEncoded());
    }

    private String loadXmlTemplate() throws IOException {
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream("samlResponsePostForm.html");
        if (inputStream == null) {
            throw new FileNotFoundException("XML template not found in resources folder.");
        }
        try (Scanner scanner = new Scanner(inputStream, StandardCharsets.UTF_8)) {
            return scanner.useDelimiter("\\A").next();
        }
    }

    private String buildSAMLPostForm(final String redirecturl, final String samlAssertion) {
        return "<html>"
                + "<body onload='document.forms[0].submit()'>"
                + "<form method='POST' action='" + redirecturl + "'>"
                + "<input type='hidden' name='SAMLResponse' value='" + samlAssertion + "'>"
                + "</form>"
                + "</body>"
                + "</html>";
    }

    private String decryptSamlAssertion(final String encryptedXMLContent, final PublicKey publicKey) throws Exception {
        // Step 1: Extract Encrypted AES Key and Assertion from XML Content
        String encryptedAESKeyBase64 = encryptedXMLContent.substring(
                encryptedXMLContent.indexOf("<EncryptedAESKey>") + 17,
                encryptedXMLContent.indexOf("</EncryptedAESKey>")
        );

        String encryptedAssertionBase64 = encryptedXMLContent.substring(
                encryptedXMLContent.indexOf("<EncryptedAssertion>") + 20,
                encryptedXMLContent.indexOf("</EncryptedAssertion>")
        );

        byte[] encryptedAESKey = Base64.getDecoder().decode(encryptedAESKeyBase64);
        byte[] encryptedAssertion = Base64.getDecoder().decode(encryptedAssertionBase64);

        // Step 2: Decrypt AES Key using RSA and Public Key
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAESKey);

        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, 0, aesKeyBytes.length, "AES");

        // Step 3: Decrypt Assertion using AES Key
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // AES with PKCS5Padding
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decryptedAssertionBytes = aesCipher.doFinal(encryptedAssertion);

        String decryptedAssertion = new String(decryptedAssertionBytes, StandardCharsets.UTF_8);

        return decryptedAssertion;
    }
}
