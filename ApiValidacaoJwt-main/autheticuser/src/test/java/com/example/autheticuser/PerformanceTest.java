package com.example.autheticuser;

import com.example.autheticuser.model.LoginRequest;
import com.example.autheticuser.service.JwtService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DisplayName("Testes de Performance - Autenticação e Autorização")
class PerformanceTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private ObjectMapper objectMapper;

    private LoginRequest loginRequest;

    @BeforeEach
    void setup() {
        loginRequest = new LoginRequest();
        loginRequest.setUsername("admin");
        loginRequest.setPassword("123456");
    }

    @Test
    @DisplayName("Geração de múltiplos tokens deve ser eficiente")
    void testMultipleTokenGeneration() throws Exception {
        int numberOfTokens = 100;
        long startTime = System.currentTimeMillis();

        for (int i = 0; i < numberOfTokens; i++) {
            String token = jwtService.generateToken("user" + i, "USER");
            assertNotNull(token);
            assertTrue(jwtService.validateToken(token));
        }

        long endTime = System.currentTimeMillis();
        long duration = endTime - startTime;

        // Deve gerar 100 tokens em menos de 5 segundos
        assertTrue(duration < 5000, "Geração de tokens demorou muito: " + duration + "ms");

        System.out.println("Gerados " + numberOfTokens + " tokens em " + duration + "ms");
        System.out.println("Média: " + (duration / (double) numberOfTokens) + "ms por token");
    }

    @Test
    @DisplayName("Validação de múltiplos tokens deve ser eficiente")
    void testMultipleTokenValidation() throws Exception {
        int numberOfTokens = 100;
        List<String> tokens = new ArrayList<>();

        // Gera tokens primeiro
        for (int i = 0; i < numberOfTokens; i++) {
            tokens.add(jwtService.generateToken("user" + i, "USER"));
        }

        // Valida todos os tokens
        long startTime = System.currentTimeMillis();

        for (String token : tokens) {
            assertTrue(jwtService.validateToken(token));
        }

        long endTime = System.currentTimeMillis();
        long duration = endTime - startTime;

        // Deve validar 100 tokens em menos de 2 segundos
        assertTrue(duration < 2000, "Validação de tokens demorou muito: " + duration + "ms");

        System.out.println("Validados " + numberOfTokens + " tokens em " + duration + "ms");
        System.out.println("Média: " + (duration / (double) numberOfTokens) + "ms por validação");
    }

    @Test
    @DisplayName("Login simultâneo de múltiplos usuários deve funcionar")
    void testConcurrentLogins() throws Exception {
        int numberOfConcurrentLogins = 10;
        ExecutorService executor = Executors.newFixedThreadPool(numberOfConcurrentLogins);
        List<CompletableFuture<Boolean>> futures = new ArrayList<>();

        long startTime = System.currentTimeMillis();

        for (int i = 0; i < numberOfConcurrentLogins; i++) {
            final int userIndex = i;
            CompletableFuture<Boolean> future = CompletableFuture.supplyAsync(() -> {
                try {
                    LoginRequest request = new LoginRequest();
                    request.setUsername("admin");
                    request.setPassword("123456");

                    MvcResult result = mockMvc.perform(post("/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                            .andExpect(status().isOk())
                            .andReturn();

                    String responseContent = result.getResponse().getContentAsString();
                    return responseContent.contains("access_token");
                } catch (Exception e) {
                    e.printStackTrace();
                    return false;
                }
            }, executor);
            futures.add(future);
        }

        // Aguarda todos os logins terminarem
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
        executor.shutdown();
        executor.awaitTermination(10, TimeUnit.SECONDS);

        long endTime = System.currentTimeMillis();
        long duration = endTime - startTime;

        // Verifica se todos os logins foram bem-sucedidos
        for (CompletableFuture<Boolean> future : futures) {
            assertTrue(future.get(), "Login simultâneo falhou");
        }

        // Deve processar 10 logins simultâneos em menos de 10 segundos
        assertTrue(duration < 10000, "Logins simultâneos demoraram muito: " + duration + "ms");

        System.out.println("Processados " + numberOfConcurrentLogins + " logins simultâneos em " + duration + "ms");
        System.out.println("Média: " + (duration / (double) numberOfConcurrentLogins) + "ms por login");
    }

    @Test
    @DisplayName("Validação simultânea de tokens deve funcionar")
    void testConcurrentTokenValidation() throws Exception {
        int numberOfTokens = 50;
        List<String> tokens = new ArrayList<>();

        // Gera tokens primeiro
        for (int i = 0; i < numberOfTokens; i++) {
            tokens.add(jwtService.generateToken("user" + i, "USER"));
        }

        ExecutorService executor = Executors.newFixedThreadPool(10);
        List<CompletableFuture<Boolean>> futures = new ArrayList<>();

        long startTime = System.currentTimeMillis();

        for (String token : tokens) {
            CompletableFuture<Boolean> future = CompletableFuture.supplyAsync(() -> {
                try {
                    return jwtService.validateToken(token);
                } catch (Exception e) {
                    e.printStackTrace();
                    return false;
                }
            }, executor);
            futures.add(future);
        }

        // Aguarda todas as validações terminarem
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
        executor.shutdown();
        executor.awaitTermination(10, TimeUnit.SECONDS);

        long endTime = System.currentTimeMillis();
        long duration = endTime - startTime;

        // Verifica se todas as validações foram bem-sucedidas
        for (CompletableFuture<Boolean> future : futures) {
            assertTrue(future.get(), "Validação simultânea falhou");
        }

        // Deve processar 50 validações simultâneas em menos de 5 segundos
        assertTrue(duration < 5000, "Validações simultâneas demoraram muito: " + duration + "ms");

        System.out.println("Processadas " + numberOfTokens + " validações simultâneas em " + duration + "ms");
        System.out.println("Média: " + (duration / (double) numberOfTokens) + "ms por validação");
    }

    @Test
    @DisplayName("Extração de username de múltiplos tokens deve ser eficiente")
    void testMultipleUsernameExtraction() throws Exception {
        int numberOfTokens = 100;
        List<String> tokens = new ArrayList<>();

        // Gera tokens primeiro
        for (int i = 0; i < numberOfTokens; i++) {
            tokens.add(jwtService.generateToken("user" + i, "USER"));
        }

        long startTime = System.currentTimeMillis();

        for (int i = 0; i < tokens.size(); i++) {
            String username = jwtService.getUsernameFromToken(tokens.get(i));
            assertEquals("user" + i, username);
        }

        long endTime = System.currentTimeMillis();
        long duration = endTime - startTime;

        // Deve extrair 100 usernames em menos de 2 segundos
        assertTrue(duration < 2000, "Extração de usernames demorou muito: " + duration + "ms");

        System.out.println("Extraídos " + numberOfTokens + " usernames em " + duration + "ms");
        System.out.println("Média: " + (duration / (double) numberOfTokens) + "ms por extração");
    }
}