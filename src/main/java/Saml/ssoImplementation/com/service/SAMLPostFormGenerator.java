package Saml.ssoImplementation.com.service;

import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class SAMLPostFormGenerator {
   /**
     * Builds a SAML POST form with the given redirect URL and fields.
     * @param redirectUrl The URL to redirect to
     * @param fields      The fields to include in the form
     * @return The HTML form as a string
     */
    public String buildSAMLPostForm(final String redirectUrl, final Map<String, String> fields) {
        StringBuilder htmlBuilder = new StringBuilder();

        // Start the HTML form
        htmlBuilder.append("<!DOCTYPE html>\n")
                .append("<html lang=\"en\">\n\n")
                .append("<body onload=\"document.forms[0].submit()\">\n")
                .append("  <form id=\"samlForm\" method=\"post\" action=\"")
                .append(redirectUrl).append("\" style=\"display: none;\" name=\"samlForm\">\n");

        // Dynamically add input fields with proper formatting
        for (Map.Entry<String, String> field : fields.entrySet()) {
            htmlBuilder.append("    <input type=\"hidden\" name=\"")
                    .append(field.getKey()).append("\" value=\"")
                    .append(field.getValue()).append("\">\n");
        }

        // Close the form and body
        htmlBuilder.append("  </form>\n")
                .append("</body>\n")
                .append("</html>");

        return htmlBuilder.toString();
    }
}

