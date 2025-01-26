package Saml.ssoImplementation.com.service;

import Saml.ssoImplementation.com.constant.Constant;
import org.springframework.stereotype.Service;


@Service
public class MetadataService implements IMetadataService {

    /**
     * Get metadata by uuid.
     *
     * @param metadataId
     * @return metadata
     */
    @Override
    public String getMetadata(final String metadataId) {

//        Optional<Metadata> optionalMetadata = metadataRepo.findById(UUID.fromString("62b44817-68e5-4569-931e-28e81bdaf0f2"));
        if (!isValidUUID(metadataId)) {
            return "Invalid Id";
        } else {
            return generateMetadataUrl();
        }
    }

    private boolean isValidUUID(final String uuid) {
        try {
            // Parse the UUID to validate its format
            java.util.UUID parsedUuid = java.util.UUID.fromString(uuid);

            // Compare the parsed UUID with the expected UUID
            return parsedUuid.equals(java.util.UUID.fromString("62x84817-68e5-4569-931e-28e81baaf0c2"));
        } catch (IllegalArgumentException e) {
            // If parsing fails, it's not a valid UUID
            return false;
        }
    }

    private String generateMetadataUrl() {

        String certificate = Constant.PUBLIC_CERTIFICATE;

        StringBuilder metadataBuilder = new StringBuilder();

        // Start of the XML metadata
        metadataBuilder.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
                .append("<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"")
                .append("Zumply").append("\">\n");

        // Add IDPSSODescriptor (Identity Provider Single Sign-On Descriptor)
        metadataBuilder.append("<IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n");

        // Add SSO Binding if available
//        if (metadata.getSsoBinding() != null && !metadata.getSsoBinding().isEmpty()) {
//            metadataBuilder.append("<SingleSignOnService Binding=\"")
//                    .append(metadata.getSsoBinding())
//                    .append("\" Location=\"")
//                    .append(metadata.getSsoUrl())
//                    .append("\"/>\n");
//        }

        // Add KeyDescriptor (Signing Certificate)
        metadataBuilder.append("<KeyDescriptor use=\"signing\">\n")
                .append("<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n")
                .append("<X509Data>\n")
                .append("<X509Certificate>")
                .append(certificate
                        .replace("-----BEGIN CERTIFICATE-----", "")
                        .replace("-----END CERTIFICATE-----", "")
                        .replaceAll("\\s+", "")) // Base64 encoded signing certificate
                .append("</X509Certificate>\n")
                .append("</X509Data>\n")
                .append("</KeyInfo>\n")
                .append("</KeyDescriptor>\n");

        // Add Encryption Certificate if available
//        if (metadata.getEncryptionCert() != null && !metadata.getEncryptionCert().isEmpty()) {
            metadataBuilder.append("<KeyDescriptor use=\"encryption\">\n")
                    .append("<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n")
                    .append("<X509Data>\n")
                    .append("<X509Certificate>")
                    .append(certificate
                            .replace("-----BEGIN CERTIFICATE-----", "")
                            .replace("-----END CERTIFICATE-----", "")
                            .replaceAll("\\s+", "")) // Base64 encoded encryption certificate
                    .append("</X509Certificate>\n")
                    .append("</X509Data>\n")
                    .append("</KeyInfo>\n")
                    .append("</KeyDescriptor>\n");
//        }

        metadataBuilder.append("<NameIDFormat>").append(Constant.NAME_ID_FORMAT).append("</NameIDFormat>\n");
//        ObjectMapper objectMapper = new ObjectMapper();
//        // Add NameID formats (From JSON stored in nameIdFormats)
//        if (metadata.getNameIdFormats() != null && !metadata.getNameIdFormats().isEmpty()) {
//            try {
//                JsonNode formats = objectMapper.readTree(metadata.getNameIdFormats().toString());
//                for (JsonNode format : formats) {
//                    metadataBuilder.append("<NameIDFormat>").append(format.asText()).append("</NameIDFormat>\n");
//                }
//            } catch (Exception e) {
//                e.printStackTrace(); // Log exception as per your logging setup
//            }
//        }

        metadataBuilder.append("</IDPSSODescriptor>\n");

        // End of the EntityDescriptor
        metadataBuilder.append("</EntityDescriptor>");

        // Return the constructed metadata as a string
        return metadataBuilder.toString();
    }
}
