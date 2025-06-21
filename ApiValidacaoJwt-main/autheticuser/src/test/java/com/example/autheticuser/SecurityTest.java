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

import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DisplayName("Testes de Segurança - Autenticação e Autorização")
class SecurityTest {

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
        @DisplayName("Token JWT deve conter claims de segurança necessárias")
        void testJwtTokenSecurityClaims() throws Exception {
                // Arrange
                MvcResult result = mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(loginRequest)))
                                .andExpect(status().isOk())
                                .andReturn();

                String responseContent = result.getResponse().getContentAsString();
                String token = objectMapper.readTree(responseContent).get("access_token").asText();

                // Act
                Map<String, Object> claims = jwtService.getAllClaimsFromToken(token);

                // Assert
                assertNotNull(claims.get("sub"), "Token deve conter subject (username)");
                assertNotNull(claims.get("iat"), "Token deve conter issued at");
                assertNotNull(claims.get("exp"), "Token deve conter expiration");
                assertNotNull(claims.get("authorities"), "Token deve conter authorities");

                // Verifica se o subject é o username correto
                assertEquals("admin", claims.get("sub"));
        }

        @Test
        @DisplayName("Token JWT deve ter tempo de expiração válido")
        void testJwtTokenExpiration() throws Exception {
                // Arrange
                MvcResult result = mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(loginRequest)))
                                .andExpect(status().isOk())
                                .andReturn();

                String responseContent = result.getResponse().getContentAsString();
                String token = objectMapper.readTree(responseContent).get("access_token").asText();

                // Act
                Map<String, Object> claims = jwtService.getAllClaimsFromToken(token);
                Long expiration = (Long) claims.get("exp");
                Long issuedAt = (Long) claims.get("iat");

                // Assert
                assertNotNull(expiration, "Token deve ter tempo de expiração");
                assertNotNull(issuedAt, "Token deve ter tempo de emissão");

                // Verifica se o token não expirou
                long currentTime = System.currentTimeMillis() / 1000;
                assertTrue(expiration > currentTime, "Token não deve estar expirado");

                // Verifica se o tempo de expiração é razoável (entre 1 hora e 24 horas)
                long tokenLifetime = expiration - issuedAt;
                assertTrue(tokenLifetime >= 3600, "Token deve ter pelo menos 1 hora de vida");
                assertTrue(tokenLifetime <= 86400, "Token não deve ter mais de 24 horas de vida");
        }

        @Test
        @DisplayName("Token JWT deve ser único para cada login")
        void testJwtTokenUniqueness() throws Exception {
                // Arrange & Act
                MvcResult result1 = mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(loginRequest)))
                                .andExpect(status().isOk())
                                .andReturn();

                MvcResult result2 = mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(loginRequest)))
                                .andExpect(status().isOk())
                                .andReturn();

                String token1 = objectMapper.readTree(result1.getResponse().getContentAsString())
                                .get("access_token").asText();
                String token2 = objectMapper.readTree(result2.getResponse().getContentAsString())
                                .get("access_token").asText();

                // Assert
                assertNotEquals(token1, token2, "Tokens devem ser únicos para cada login");

                // Ambos devem ser válidos
                assertTrue(jwtService.validateToken(token1));
                assertTrue(jwtService.validateToken(token2));
        }

        @Test
        @DisplayName("Token JWT deve conter role correta do usuário")
        void testJwtTokenRoleClaim() throws Exception {
                // Arrange
                LoginRequest userLoginRequest = new LoginRequest();
                userLoginRequest.setUsername("user");
                userLoginRequest.setPassword("password");

                // Act
                MvcResult result = mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(userLoginRequest)))
                                .andExpect(status().isOk())
                                .andReturn();

                String responseContent = result.getResponse().getContentAsString();
                String token = objectMapper.readTree(responseContent).get("access_token").asText();
                Map<String, Object> claims = jwtService.getAllClaimsFromToken(token);

                // Assert
                assertNotNull(claims.get("authorities"), "Token deve conter authorities");
                // Verifica se contém a role USER
                assertTrue(claims.get("authorities").toString().contains("ROLE_USER"));
        }

        @Test
        @DisplayName("Token JWT deve ser inválido quando modificado")
        void testJwtTokenTampering() throws Exception {
                // Arrange
                MvcResult result = mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(loginRequest)))
                                .andExpect(status().isOk())
                                .andReturn();

                String responseContent = result.getResponse().getContentAsString();
                String originalToken = objectMapper.readTree(responseContent).get("access_token").asText();

                // Act - Modifica o token
                String[] parts = originalToken.split("\\.");
                String tamperedPayload = Base64.getUrlEncoder().withoutPadding()
                                .encodeToString("{\"sub\":\"hacker\",\"authorities\":[\"ROLE_admin\"]}".getBytes());
                String tamperedToken = parts[0] + "." + tamperedPayload + "." + parts[2];

                // Assert
                assertFalse(jwtService.validateToken(tamperedToken), "Token modificado deve ser inválido");
        }

        @Test
        @DisplayName("Token JWT deve ser inválido quando assinatura é removida")
        void testJwtTokenWithoutSignature() throws Exception {
                // Arrange
                MvcResult result = mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(loginRequest)))
                                .andExpect(status().isOk())
                                .andReturn();

                String responseContent = result.getResponse().getContentAsString();
                String originalToken = objectMapper.readTree(responseContent).get("access_token").asText();

                // Act - Remove a assinatura
                String[] parts = originalToken.split("\\.");
                String tokenWithoutSignature = parts[0] + "." + parts[1] + ".";

                // Assert
                assertFalse(jwtService.validateToken(tokenWithoutSignature), "Token sem assinatura deve ser inválido");
        }

        @Test
        @DisplayName("Endpoint protegido deve rejeitar token malformado")
        void testProtectedEndpointRejectsMalformedToken() throws Exception {
                // Act & Assert
                mockMvc.perform(get("/api/hello")
                                .header("Authorization", "Bearer malformed.token.here"))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Endpoint protegido deve rejeitar token com formato incorreto")
        void testProtectedEndpointRejectsInvalidFormat() throws Exception {
                // Act & Assert
                mockMvc.perform(get("/api/hello")
                                .header("Authorization", "InvalidFormat token123"))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Endpoint protegido deve rejeitar token vazio")
        void testProtectedEndpointRejectsEmptyToken() throws Exception {
                // Act & Assert
                mockMvc.perform(get("/api/hello")
                                .header("Authorization", "Bearer "))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Endpoint protegido deve rejeitar quando não há header Authorization")
        void testProtectedEndpointRejectsNoAuthorization() throws Exception {
                // Act & Assert
                mockMvc.perform(get("/api/hello"))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Login deve falhar com credenciais vazias")
        void testLoginFailsWithEmptyCredentials() throws Exception {
                // Arrange
                LoginRequest emptyRequest = new LoginRequest();
                emptyRequest.setUsername("");
                emptyRequest.setPassword("");

                // Act & Assert
                mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(emptyRequest)))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Login deve falhar com credenciais null")
        void testLoginFailsWithNullCredentials() throws Exception {
                // Arrange
                LoginRequest nullRequest = new LoginRequest();
                nullRequest.setUsername(null);
                nullRequest.setPassword(null);

                // Act & Assert
                mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(nullRequest)))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Validação de token deve falhar com token vazio")
        void testTokenValidationFailsWithEmptyToken() throws Exception {
                // Act & Assert
                mockMvc.perform(post("/auth/validate")
                                .param("token", ""))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Validação de token deve falhar com token null")
        void testTokenValidationFailsWithNullToken() throws Exception {
                // Act & Assert
                mockMvc.perform(post("/auth/validate")
                                .param("token", "null"))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Token JWT deve conter apenas informações necessárias")
        void testJwtTokenMinimalInformation() throws Exception {
                // Arrange
                MvcResult result = mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(loginRequest)))
                                .andExpect(status().isOk())
                                .andReturn();

                String responseContent = result.getResponse().getContentAsString();
                String token = objectMapper.readTree(responseContent).get("access_token").asText();

                // Act
                Map<String, Object> claims = jwtService.getAllClaimsFromToken(token);

                // Assert
                // Verifica se contém apenas as claims necessárias
                assertTrue(claims.containsKey("sub"), "Deve conter subject");
                assertTrue(claims.containsKey("iat"), "Deve conter issued at");
                assertTrue(claims.containsKey("exp"), "Deve conter expiration");
                assertTrue(claims.containsKey("authorities"), "Deve conter authorities");

                // Verifica se não contém informações sensíveis
                assertFalse(claims.containsKey("password"), "Não deve conter senha");
                assertFalse(claims.containsKey("secret"), "Não deve conter informações secretas");
        }
}