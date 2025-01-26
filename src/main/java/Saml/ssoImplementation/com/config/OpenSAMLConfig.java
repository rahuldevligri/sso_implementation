package Saml.ssoImplementation.com.config;

import org.opensaml.core.config.InitializationService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenSAMLConfig {

    /**
     * Initializes the OpenSAML library.
     */
    @Bean
    public Object initializeOpenSAML() {
        try {
            // Initialize OpenSAML library
            InitializationService.initialize();
            return new Object();
        } catch (Exception e) {
            throw new RuntimeException("Error initializing OpenSAML", e);
        }
    }
}
