package Saml.ssoImplementation.com.controller;

import Saml.ssoImplementation.com.service.ISamlSsoService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/public/v3/sso-saml")
public class SamlSsoController {

    @Autowired
    private ISamlSsoService iSamlSsoService;

    /**
     *
     * @param sp
     * @param response
     * @throws Exception
     */
    @GetMapping("/goto/{sp}")
    public void redirectToSp(final @PathVariable("sp") String sp, final HttpServletResponse response) throws Exception {
        // Step 1: Generate the signed SAML assertion and Build an HTML form with the SAML response
        String htmlForm = iSamlSsoService.generateSamlAssertion(sp);

        // Step 2: Write the form to the response (auto-submits in the browser)
        response.setContentType("text/html");
        response.getWriter().write(htmlForm);
    }
}


