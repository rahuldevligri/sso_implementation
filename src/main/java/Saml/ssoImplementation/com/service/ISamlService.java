package Saml.ssoImplementation.com.service;

public interface ISamlService {
    String generateSamlAssertion(String sp) throws Exception;
}