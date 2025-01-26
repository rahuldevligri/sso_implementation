package Saml.ssoImplementation.com.controller;

import Saml.ssoImplementation.com.service.ISamlService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/public/api/v4/security-central")
public class SamlController {

    @Autowired
    private ISamlService iSamlService;

    @GetMapping("/sso/email/{email}")
    public void redirectToSp(@PathVariable String email, HttpServletResponse response) throws Exception {
        System.out.println(email);
        // Generate SAML assertion and HTML form
        String htmlForm = iSamlService.generateSamlAssertion(email);
        if (htmlForm == null || htmlForm.isEmpty()) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("Failed to generate SAML assertion");
            return;
        }

        // Set the response content type and write the HTML form to the response
        response.setContentType("text/html");
        response.getWriter().write(htmlForm);
        response.getWriter().flush();
    }
}
