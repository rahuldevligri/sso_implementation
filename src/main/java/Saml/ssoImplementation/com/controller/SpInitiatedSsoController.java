package Saml.ssoImplementation.com.controller;

import Saml.ssoImplementation.com.service.ISpInitiatedSsoService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/restricted/api/v4/security-central")
public class SpInitiatedSsoController {

    @Autowired
    private ISpInitiatedSsoService ispInitiatedSsoService;

    /**
     * Handle request.
     * @param body
     * @return ssoUrl
     * @throws Exception
     */
    @PostMapping("/sp-initiated/sso")
    public void handleRequest(@RequestBody final String body,
                              final HttpServletResponse response) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(body);

        String email = jsonNode.get("email").asText();

        String htmlForm = ispInitiatedSsoService.generateSAMLRequest();

        response.setContentType("text/html");
        response.getWriter().write(htmlForm);
        response.getWriter().flush();
    }
}
