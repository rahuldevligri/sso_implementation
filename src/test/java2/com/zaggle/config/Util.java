package com.zaggle.config;

import org.springframework.core.io.ClassPathResource;
import org.springframework.util.FileCopyUtils;

import java.nio.charset.StandardCharsets;

public class Util {
    public static String loadJsonFromFile(final String jsonName) throws Exception {
        ClassPathResource resource = new ClassPathResource(jsonName);
        return new String(FileCopyUtils.copyToByteArray(resource.getInputStream()), StandardCharsets.UTF_8);
    }
}
