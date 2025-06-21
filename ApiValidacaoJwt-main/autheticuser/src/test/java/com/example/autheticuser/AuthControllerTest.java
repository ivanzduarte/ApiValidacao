package com.example.autheticuser;

import com.example.autheticuser.controller.AuthController;
import com.example.autheticuser.model.LoginRequest;
import com.example.autheticuser.service.AuthService;
import com.example.autheticuser.service.JwtService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("Testes Unitários - AuthController")
class AuthControllerTest {

    @Mock
    private AuthService authService;

    @Mock
    private JwtService jwtService;

    @InjectMocks
    private AuthController authController;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(authController).build();
        objectMapper = new ObjectMapper();
    }

    @Test
    @DisplayName("Login bem-sucedido deve retornar 200 com token")
    void testLogin_Success() throws Exception {
        // Arrange
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername("testuser");
        loginRequest.setPassword("password123");

        String expectedToken = "jwt.token.here";
        when(authService.authenticateUserAndGenerateToken("testuser", "password123"))
                .thenReturn(expectedToken);

        // Act & Assert
        mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.access_token").value(expectedToken));

        verify(authService).authenticateUserAndGenerateToken("testuser", "password123");
    }

    @Test
    @DisplayName("Login com credenciais inválidas deve retornar 401")
    void testLogin_BadCredentials() throws Exception {
        // Arrange
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername("testuser");
        loginRequest.setPassword("wrongpassword");

        when(authService.authenticateUserAndGenerateToken("testuser", "wrongpassword"))
                .thenThrow(new BadCredentialsException("Credenciais inválidas"));

        // Act & Assert
        mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Credenciais inválidas"));

        verify(authService).authenticateUserAndGenerateToken("testuser", "wrongpassword");
    }

    @Test
    @DisplayName("Login com exceção genérica deve retornar 500")
    void testLogin_GenericException() throws Exception {
        // Arrange
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername("testuser");
        loginRequest.setPassword("password123");

        when(authService.authenticateUserAndGenerateToken("testuser", "password123"))
                .thenThrow(new RuntimeException("Erro interno"));

        // Act & Assert
        mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.error").value("Ocorreu um erro interno ao tentar logar."));

        verify(authService).authenticateUserAndGenerateToken("testuser", "password123");
    }

    @Test
    @DisplayName("Validação de token válido deve retornar 200")
    void testValidateToken_ValidToken() throws Exception {
        // Arrange
        String token = "valid.jwt.token";
        String username = "testuser";

        when(jwtService.validateToken(token)).thenReturn(true);
        when(jwtService.getUsernameFromToken(token)).thenReturn(username);

        // Act & Assert
        mockMvc.perform(post("/auth/validate")
                .param("token", token))
                .andExpect(status().isOk())
                .andExpect(content().string("Token válido! Username: " + username));

        verify(jwtService).validateToken(token);
        verify(jwtService).getUsernameFromToken(token);
    }

    @Test
    @DisplayName("Validação de token inválido deve retornar 401")
    void testValidateToken_InvalidToken() throws Exception {
        // Arrange
        String token = "invalid.jwt.token";

        when(jwtService.validateToken(token)).thenReturn(false);

        // Act & Assert
        mockMvc.perform(post("/auth/validate")
                .param("token", token))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Token inválido ou expirado."));

        verify(jwtService).validateToken(token);
        verify(jwtService, never()).getUsernameFromToken(anyString());
    }

    @Test
    @DisplayName("Teste direto do método login com sucesso")
    void testLoginMethod_Success() {
        // Arrange
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername("testuser");
        loginRequest.setPassword("password123");

        String expectedToken = "jwt.token.here";
        when(authService.authenticateUserAndGenerateToken("testuser", "password123"))
                .thenReturn(expectedToken);

        // Act
        ResponseEntity<Map<String, String>> response = authController.login(loginRequest);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Bearer", response.getBody().get("token_type"));
        assertEquals(expectedToken, response.getBody().get("access_token"));
    }

    @Test
    @DisplayName("Teste direto do método login com BadCredentialsException")
    void testLoginMethod_BadCredentials() {
        // Arrange
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername("testuser");
        loginRequest.setPassword("wrongpassword");

        when(authService.authenticateUserAndGenerateToken("testuser", "wrongpassword"))
                .thenThrow(new BadCredentialsException("Credenciais inválidas"));

        // Act
        ResponseEntity<Map<String, String>> response = authController.login(loginRequest);

        // Assert
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals("Credenciais inválidas", response.getBody().get("error"));
    }

    @Test
    @DisplayName("Teste direto do método login com exceção genérica")
    void testLoginMethod_GenericException() {
        // Arrange
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername("testuser");
        loginRequest.setPassword("password123");

        when(authService.authenticateUserAndGenerateToken("testuser", "password123"))
                .thenThrow(new RuntimeException("Erro interno"));

        // Act
        ResponseEntity<Map<String, String>> response = authController.login(loginRequest);

        // Assert
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals("Ocorreu um erro interno ao tentar logar.", response.getBody().get("error"));
    }

    @Test
    @DisplayName("Teste direto do método validateToken com token válido")
    void testValidateTokenMethod_ValidToken() {
        // Arrange
        String token = "valid.jwt.token";
        String username = "testuser";

        when(jwtService.validateToken(token)).thenReturn(true);
        when(jwtService.getUsernameFromToken(token)).thenReturn(username);

        // Act
        ResponseEntity<String> response = authController.validateToken(token);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Token válido! Username: " + username, response.getBody());
    }

    @Test
    @DisplayName("Teste direto do método validateToken com token inválido")
    void testValidateTokenMethod_InvalidToken() {
        // Arrange
        String token = "invalid.jwt.token";

        when(jwtService.validateToken(token)).thenReturn(false);

        // Act
        ResponseEntity<String> response = authController.validateToken(token);

        // Assert
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals("Token inválido ou expirado.", response.getBody());
    }

    @Test
    @DisplayName("Login com JSON malformado deve retornar erro")
    void testLogin_MalformedJson() throws Exception {
        // Act & Assert
        mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"invalid\": json}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Validação sem token deve retornar erro")
    void testValidateToken_NoToken() throws Exception {
        // Act & Assert
        mockMvc.perform(post("/auth/validate"))
                .andExpect(status().isBadRequest());
    }
}