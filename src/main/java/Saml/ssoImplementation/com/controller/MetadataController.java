package Saml.ssoImplementation.com.controller;

import Saml.ssoImplementation.com.service.IMetadataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/public/v3/sso-metadata")
public class MetadataController {

    @Autowired
    private IMetadataService metadataService;

    /**
     * Get metadata by uuid.
     *
     * @param metadataId
     * @return metadata
     */
    @GetMapping(value = "/{uuid}", produces = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<String> getMetadata(@PathVariable("uuid") final String metadataId) {

        String metadata = metadataService.getMetadata(metadataId);
        return ResponseEntity.ok(metadata);
    }
}
