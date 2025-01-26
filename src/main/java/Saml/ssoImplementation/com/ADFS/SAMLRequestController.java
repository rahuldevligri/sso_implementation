package Saml.ssoImplementation.com.ADFS;

import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;

@RestController
public class SAMLRequestController {

    private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    @Autowired
    public SAMLRequestController(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
        this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository;
    }

    @GetMapping("/saml2/authenticate/{registrationId}")
    public String generateSAMLRequest(@PathVariable String registrationId) {
        RelyingPartyRegistration registration = relyingPartyRegistrationRepository.findByRegistrationId(registrationId);
        if (registration == null) {
            return "Registration not found";
        }

        // Build AuthnRequest here
        AuthnRequest authnRequest = buildAuthnRequest(registration);
        return authnRequest.toString();
    }

    private AuthnRequest buildAuthnRequest(RelyingPartyRegistration registration) {
        AuthnRequest authnRequest = new AuthnRequestBuilder().buildObject();

        // Set basic attributes
        authnRequest.setIssueInstant(ZonedDateTime.now(ZoneOffset.UTC).toInstant());
        authnRequest.setVersion(SAMLVersion.VERSION_20);
        authnRequest.setDestination(registration.getAssertingPartyDetails().getSingleSignOnServiceLocation()); // IdP SSO URL
        authnRequest.setAssertionConsumerServiceURL(registration.getAssertionConsumerServiceLocation()); // SP ACS URL

        // Configure NameIDPolicy
        NameIDPolicy nameIDPolicy = new NameIDPolicyBuilder().buildObject();
        nameIDPolicy.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"); // Set appropriate format
        nameIDPolicy.setAllowCreate(true); // Allow the creation of new identifiers if needed
        authnRequest.setNameIDPolicy(nameIDPolicy);

        // Configure RequestedAuthnContext
        RequestedAuthnContext requestedAuthnContext = new RequestedAuthnContextBuilder().buildObject();
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
        authnRequest.setRequestedAuthnContext(requestedAuthnContext);

        // Optionally set the protocol binding (e.g., HTTP-POST)
        authnRequest.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");

        return authnRequest;
    }

}
