package Saml.ssoImplementation.com.ADFS;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
public class SamlConfig implements WebMvcConfigurer {

    @Bean
    public InMemoryRelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
        String clientId = "adfs";
        SamlConfiguration.SamlConfigData samlConfig = SamlConfiguration.getSamlConfig(clientId);

        if (samlConfig == null) {
            throw new RuntimeException("SAML configuration not found for client: " + clientId);
        }

        RelyingPartyRegistration bluestarAdfs = RelyingPartyRegistrations
                .fromMetadataLocation("classpath:/templates/metadata.xml")
                .registrationId(clientId)
                .assertionConsumerServiceLocation(samlConfig.getAssertionConsumerServiceUrl())
                .entityId(samlConfig.getEntityId())
                .build();

        logRelyingPartyDetails(bluestarAdfs);

        return new InMemoryRelyingPartyRegistrationRepository(bluestarAdfs);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorize -> authorize
                        .requestMatchers("/saml2/service-provider-metadata/**").permitAll()
                        .anyRequest().authenticated())
                .saml2Login(saml2 -> saml2
                        .loginProcessingUrl("/saml2/authenticate/{registrationId}"));
        return http.build();
    }

    private void logRelyingPartyDetails(RelyingPartyRegistration registration) {
        StringBuilder sb = new StringBuilder();
        sb.append("Relying Party Details:\n");
        sb.append("RegistrationId: ").append(registration.getRegistrationId()).append("\n");
        sb.append("EntityId: ").append(registration.getEntityId()).append("\n");
        sb.append("AssertionConsumerServiceLocation: ").append(registration.getAssertionConsumerServiceLocation()).append("\n");
        sb.append("AssertionConsumerServiceBinding: ").append(registration.getAssertionConsumerServiceBinding()).append("\n");
        sb.append("SingleLogoutServiceLocation: ").append(registration.getSingleLogoutServiceLocation()).append("\n");
        sb.append("SingleLogoutServiceBinding: ").append(registration.getSingleLogoutServiceBinding()).append("\n");
        sb.append("NameIdFormat: ").append(registration.getNameIdFormat()).append("\n");
        sb.append("DecryptionX509Credentials: ").append(formatX509Credentials(registration.getDecryptionX509Credentials())).append("\n");
        sb.append("SigningX509Credentials: ").append(formatX509Credentials(registration.getSigningX509Credentials())).append("\n");

        RelyingPartyRegistration.AssertingPartyDetails assertingDetails = registration.getAssertingPartyDetails();
        sb.append("Asserting Party Details:\n");
        sb.append("\tEntityID: ").append(assertingDetails.getEntityId()).append("\n");
        sb.append("\tWantAuthnRequestsSigned: ").append(assertingDetails.getWantAuthnRequestsSigned()).append("\n");
        sb.append("\tSigningAlgorithms: ").append(formatList(assertingDetails.getSigningAlgorithms())).append("\n");
        sb.append("\tVerificationX509Credentials: ").append(formatX509Credentials(assertingDetails.getVerificationX509Credentials())).append("\n");
        sb.append("\tEncryptionX509Credentials: ").append(formatX509Credentials(assertingDetails.getEncryptionX509Credentials())).append("\n");
        sb.append("\tSingleSignOnServiceLocation: ").append(assertingDetails.getSingleSignOnServiceLocation()).append("\n");
        sb.append("\tSingleSignOnServiceBinding: ").append(assertingDetails.getSingleSignOnServiceBinding()).append("\n");

        System.out.println(sb.toString());
    }

    private String formatX509Credentials(Collection<Saml2X509Credential> credentials) {
        if (credentials == null || credentials.isEmpty()) {
            return "[]";
        }
        return credentials.stream()
                .map(credential -> String.format(
                        "{Certificate: %s}",
                        getCertificateInfo(credential.getCertificate())
                ))
                .collect(Collectors.joining(", ", "[", "]"));
    }

    private String formatList(List<?> list) {
        return list == null || list.isEmpty() ? "[]" : list.stream()
                .map(Object::toString)
                .collect(Collectors.joining(", ", "[", "]"));
    }

    private String getCertificateInfo(X509Certificate certificate) {
        if (certificate == null) {
            return "null";
        }
        return String.format("Subject: %s, Issuer: %s, SerialNumber: %s",
                certificate.getSubjectX500Principal().getName(),
                certificate.getIssuerX500Principal().getName(),
                certificate.getSerialNumber());
    }
}
