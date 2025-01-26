package com.zaggle;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
public class AppTests {
    @Test
    public void test() {
        assertEquals("TEST", "TEST");
    }
}
