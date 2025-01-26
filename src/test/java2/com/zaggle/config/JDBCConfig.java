package com.zaggle.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;

@TestConfiguration
public class JDBCConfig {
    /**
     * Method to create a DataSource bean.
     * @return The DataSource bean.
     */
    @Bean
    public DataSource dataSource() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("org.h2.Driver");
        dataSource.setUrl("jdbc:h2:mem:platform-svc;DB_CLOSE_DELAY=-1;MODE=PostgreSQL");
        dataSource.setUsername("platform-svc");
        dataSource.setPassword("password");
        return dataSource;
    }
    /**
     * Method to create a JdbcTemplate bean.
     * @param dataSource The DataSource bean.
     * @return The JdbcTemplate bean.
     */
    @Bean
    public JdbcTemplate jdbcTemplate(final DataSource dataSource) {
        return new JdbcTemplate(dataSource);
    }
}
