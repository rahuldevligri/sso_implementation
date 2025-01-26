package Saml.ssoImplementation.com.ADFS;

import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.impl.AssertionConsumerServiceBuilder;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.SPSSODescriptorBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Element;

import javax.xml.transform.TransformerFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.dom.DOMSource;
import java.io.StringWriter;

@RestController
public class MetaDataController {

    private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    @Autowired
    public MetaDataController(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
        this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository;
    }

    // Endpoint to generate Service Provider metadata
    @GetMapping("/saml2/service-provider-metadata/{registrationId}")
    public ResponseEntity<String> getServiceProviderMetadata(@PathVariable String registrationId) {
        RelyingPartyRegistration registration = relyingPartyRegistrationRepository.findByRegistrationId(registrationId);

        if (registration == null) {
            return ResponseEntity.notFound().build();
        }

        // Generate the SP metadata XML
        String metadata = generateSamlMetadata(registration);
        return ResponseEntity.ok(metadata);
    }

    private String generateSamlMetadata(RelyingPartyRegistration registration) {
        XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

        // Build the entity descriptor
        EntityDescriptor entityDescriptor = new EntityDescriptorBuilder().buildObject();
        entityDescriptor.setEntityID(registration.getEntityId());

        // Build SPSSODescriptor (Service Provider)
        SPSSODescriptor spDescriptor = new SPSSODescriptorBuilder().buildObject();
        spDescriptor.setAuthnRequestsSigned(false);
        spDescriptor.setWantAssertionsSigned(true);

        // Add AssertionConsumerService element
        AssertionConsumerService assertionConsumerService = new AssertionConsumerServiceBuilder().buildObject();
        assertionConsumerService.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        assertionConsumerService.setLocation(registration.getAssertionConsumerServiceLocation()); // Correct this line
        assertionConsumerService.setIndex(1);
        assertionConsumerService.setIsDefault(true);

        spDescriptor.getAssertionConsumerServices().add(assertionConsumerService); // Add the AssertionConsumerService

        // Add SPSSODescriptor to the entity descriptor
        entityDescriptor.getRoleDescriptors().add(spDescriptor);

        // Marshal the entity descriptor to XML using OpenSAML Marshaller
        try {
            // Use MarshallingUtils instead of XMLObjectSupport
            Element element = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(entityDescriptor).marshall(entityDescriptor);
            // Convert the DOM element to a string
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(element), new StreamResult(writer));
            return writer.toString();
        } catch (Exception e) {
            throw new RuntimeException("Error generating metadata XML", e);
        }
    }
}
