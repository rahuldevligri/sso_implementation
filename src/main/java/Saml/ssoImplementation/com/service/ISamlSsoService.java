package Saml.ssoImplementation.com.service;

public interface ISamlSsoService {
    String generateSamlAssertion(String sp) throws Exception;
}
