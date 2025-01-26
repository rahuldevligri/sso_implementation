package Saml.ssoImplementation.com.ADFS;

import java.util.HashMap;
import java.util.Map;

public class SamlConfiguration {

    // Simulated database of client-specific SAML configurations
    private static final Map<String, SamlConfigData> samlConfigDatabase = new HashMap<>();

    static {
        // Bluestar ADFS Configuration Example
        samlConfigDatabase.put("adfs", new SamlConfigData(
                "zumply.in",
                "https://client.adfs.com",
                "https://zumply.com/login/sso?id=x7773e27-864c-4c59-80xb-d0d2db34e7ab",
                "https://adfs.client.com/adfs/services/trust",
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        ));
    } // SP Entity ID, IdP SSO URL, SP ACS URL, IdP Entity ID, Name ID Format

    public static SamlConfigData getSamlConfig(String clientId) {
        return samlConfigDatabase.get(clientId);
    }

    public static class SamlConfigData {
        private final String entityId;
        private final String ssoUrl;
        private final String assertionConsumerServiceUrl;
        private final String assertingPartyEntityId;
        private final String nameIdFormat;

        public SamlConfigData(String entityId, String ssoUrl, String assertionConsumerServiceUrl, String assertingPartyEntityId, String nameIdFormat) {
            this.entityId = entityId;
            this.ssoUrl = ssoUrl;
            this.assertionConsumerServiceUrl = assertionConsumerServiceUrl;
            this.assertingPartyEntityId = assertingPartyEntityId;
            this.nameIdFormat = nameIdFormat;
        }

        // Getters
        public String getEntityId() {
            return entityId;
        }

        public String getSsoUrl() {
            return ssoUrl;
        }

        public String getAssertionConsumerServiceUrl() {
            return assertionConsumerServiceUrl;
        }

        public String getAssertingPartyEntityId() {
            return assertingPartyEntityId;
        }

        public String getNameIdFormat() {
            return nameIdFormat;
        }
    }
}
