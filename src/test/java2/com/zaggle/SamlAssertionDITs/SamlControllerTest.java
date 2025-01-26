package com.zaggle.SamlAssertionDITs;

import com.zaggle.config.H2TestConfig;
import com.zaggle.config.JDBCConfig;
import com.zaggle.controller.SamlController;
import com.zaggle.persistence.config.PrimaryDataSourceConfig;
import com.zaggle.persistence.entity.Metadata;
import com.zaggle.persistence.repository.MetadataRepo;
import com.zaggle.service.ISamlService;
import com.zaggle.service.SamlService;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;

import java.io.PrintWriter;
import java.io.StringWriter;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("checkstyle:LineLength")
@SpringBootTest
@ActiveProfiles("test")
@ContextConfiguration(classes = {SamlController.class, SamlService.class, ISamlService.class, Metadata.class, MetadataRepo.class, JDBCConfig.class, H2TestConfig.class, PrimaryDataSourceConfig.class})
public class SamlControllerTest {
    @Autowired
    private SamlController samlController;
    @Autowired
    private HttpServletResponse response;
    @Test
    void testRedirectToPaxes() throws Exception {

        String sp = "paxes";
        String expectedSamlAssertion =
                "<html><body onload='document.forms[0].submit()'>"
                        + "<form method='POST' action='https://zaggle.paxes.com/saml2/signin/8fa8039z3z32'>"
                        + "<input type='hidden' name='SAMLResponse' value='"
                        + "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPEVuY3J5cHRlZFNBTUw+"
                        + "CiAgICA8RW5jcnlwdGVkQUVTS2V5PmFPVjVLbXAxelpMYlgvQnh4RGJJZTdKRXJyMCtrZ2Jz"
                        + "NG9DYzNqS05YVzJtcU1uNmxtdTdtMWJjNHRpeWVZZXFKNXU1cFlEWFZMSW42L0YzQy9YZjFa"
                        + "Zml6OC8xekJ1OXRpQjRwaDdTV0hVcVp0Q1ZyUW52RlJOa0lFNTNxY0dpdXVITHp5Wk5iZ0dG"
                        + "Z2xmQVV1Uy8rTUozU25kMU91NUVSNFY5VUtiTFNUWUMrblp3SUZJd3NMV2djTnBHZmovbGJETH"
                        + "IzT01UQkFxMFhMbENxLy9qQzVXZWxFRFYvQllyVmYzbERLK2NlWmc2c3FpOHlzU29wRUxQNXRy"
                        + "/zZvX3BvZ2ltOUg5Q2lOXXBPZGluYmN5ckF4ZzZ2d8kLW9//LxcNXjc60Q=="
                        + "</form></body></html>";

        // Create a MockHttpServletResponse
        // Obtain the PrintWriter from the response
//        PrintWriter writer = response.getWriter();

        // Call the method that writes the SAML assertion
        samlController.redirectToSp(sp, response);

        // Assert that the content type is as expected
        assertEquals("text/html", response.getContentType());

        // Capture the written content
//        String actualContent = response.getWriter().toString(); // Get the response content as a String
//        System.out.println("dasd:" + actualContent.toString());
//        // Compare the expected SAML assertion with the actual content
//        assertEquals(expectedSamlAssertion, actualContent);

//        assertEquals(expectedSamlAssertion, response.getc() ) ;
//        assertEquals("ISO-8859-1", response.getCharacterEncoding());
//        assertEquals(200, response.getStatus());
//        assertEquals(4096, response.getBufferSize());
//        assertEquals(null, response.getTrailerFields());

    }
}
