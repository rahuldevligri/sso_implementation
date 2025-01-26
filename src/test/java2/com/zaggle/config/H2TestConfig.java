package com.zaggle.config;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.ResourceUtils;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

@Configuration
public class H2TestConfig {
    @Autowired
    private JdbcTemplate jdbcTemplate;
    /**
     * Method to create a MockedStatic bean for ExceptionHelperV2.
     */
    @PostConstruct
    public void init() {
        String[] sqlFilePaths = {
                "classpath:h2-data/schema.sql",
                "classpath:h2-data/insert-data.sql"
        };

        for (String sqlFilePath : sqlFilePaths) {
            executeSqlFromFile(sqlFilePath);
        }
    }
    private void executeSqlFromFile(final String filePath) {
        try (BufferedReader br = new BufferedReader(new FileReader(ResourceUtils.getFile(filePath)))) {
            String line;
            StringBuilder sql = new StringBuilder();
            while ((line = br.readLine()) != null) {
                sql.append(line).append("\n");
            }
            jdbcTemplate.execute(sql.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
