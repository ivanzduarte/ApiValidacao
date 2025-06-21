package com.example.autheticuser;

import com.example.autheticuser.service.JwtService;
import io.jsonwebtoken.ExpiredJwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("Testes Unitários - JwtService")
class JwtServiceTest {

    @InjectMocks
    private JwtService jwtService;

    private static final String SECRET_KEY = "chaveUltraSecretaSuperSeguraQueVocePodeMudar123";
    private static final long EXPIRATION_TIME = 3600000; // 1 hora

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(jwtService, "secretKey", SECRET_KEY);
        ReflectionTestUtils.setField(jwtService, "expirationTime", EXPIRATION_TIME);
    }

    @Test
    @DisplayName("Geração de token deve criar token válido")
    void testGenerateToken_Success() {
        // Arrange
        String username = "testuser";
        String role = "USER";

        // Act
        String token = jwtService.generateToken(username, role);

        // Assert
        assertNotNull(token);
        assertTrue(token.split("\\.").length == 3); // JWT tem 3 partes
        assertTrue(jwtService.validateToken(token));
        assertEquals(username, jwtService.getUsernameFromToken(token));
    }

    @Test
    @DisplayName("Token gerado deve conter claims corretas")
    void testGenerateToken_ContainsCorrectClaims() {
        // Arrange
        String username = "admin";
        String role = "admin";

        // Act
        String token = jwtService.generateToken(username, role);
        Map<String, Object> claims = jwtService.getAllClaimsFromToken(token);

        // Assert
        assertEquals(username, claims.get("sub")); // subject
        assertNotNull(claims.get("iat")); // issued at
        assertNotNull(claims.get("exp")); // expiration
        assertNotNull(claims.get("authorities")); // authorities claim
    }

    @Test
    @DisplayName("Validação de token válido deve retornar true")
    void testValidateToken_ValidToken() {
        // Arrange
        String token = jwtService.generateToken("testuser", "USER");

        // Act
        boolean isValid = jwtService.validateToken(token);

        // Assert
        assertTrue(isValid);
    }

    @Test
    @DisplayName("Validação de token inválido deve retornar false")
    void testValidateToken_InvalidToken() {
        // Arrange
        String invalidToken = "invalid.token.here";

        // Act
        boolean isValid = jwtService.validateToken(invalidToken);

        // Assert
        assertFalse(isValid);
    }

    @Test
    @DisplayName("Validação de token malformado deve retornar false")
    void testValidateToken_MalformedToken() {
        // Arrange
        String malformedToken = "not.a.valid.jwt.token";

        // Act
        boolean isValid = jwtService.validateToken(malformedToken);

        // Assert
        assertFalse(isValid);
    }

    @Test
    @DisplayName("Extração de username de token válido deve funcionar")
    void testGetUsernameFromToken_ValidToken() {
        // Arrange
        String username = "testuser";
        String token = jwtService.generateToken(username, "USER");

        // Act
        String extractedUsername = jwtService.getUsernameFromToken(token);

        // Assert
        assertEquals(username, extractedUsername);
    }

    @Test
    @DisplayName("Extração de username de token inválido deve lançar exceção")
    void testGetUsernameFromToken_InvalidToken() {
        // Arrange
        String invalidToken = "invalid.token.here";

        // Act & Assert
        assertThrows(Exception.class, () -> {
            jwtService.getUsernameFromToken(invalidToken);
        });
    }

    @Test
    @DisplayName("Extração de claims de token válido deve retornar todas as claims")
    void testGetAllClaimsFromToken_ValidToken() {
        // Arrange
        String username = "testuser";
        String role = "USER";
        String token = jwtService.generateToken(username, role);

        // Act
        Map<String, Object> claims = jwtService.getAllClaimsFromToken(token);

        // Assert
        assertNotNull(claims);
        assertEquals(username, claims.get("sub"));
        assertNotNull(claims.get("iat"));
        assertNotNull(claims.get("exp"));
        assertNotNull(claims.get("authorities"));
    }

    @Test
    @DisplayName("Tokens gerados em momentos diferentes devem ser diferentes")
    void testGenerateToken_DifferentTokensForSameUser() {
        // Arrange
        String username = "testuser";
        String role = "USER";

        // Act
        String token1 = jwtService.generateToken(username, role);

        // Simula pequeno delay
        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        String token2 = jwtService.generateToken(username, role);

        // Assert
        assertNotEquals(token1, token2);
        assertTrue(jwtService.validateToken(token1));
        assertTrue(jwtService.validateToken(token2));
        assertEquals(username, jwtService.getUsernameFromToken(token1));
        assertEquals(username, jwtService.getUsernameFromToken(token2));
    }

    @Test
    @DisplayName("Token com role admin deve conter authorities corretas")
    void testGenerateToken_AdminRole() {
        // Arrange
        String username = "admin";
        String role = "admin";

        // Act
        String token = jwtService.generateToken(username, role);
        Map<String, Object> claims = jwtService.getAllClaimsFromToken(token);

        // Assert
        assertEquals(username, claims.get("sub"));
        assertNotNull(claims.get("authorities"));
    }

    @Test
    @DisplayName("Token com role MANAGER deve conter authorities corretas")
    void testGenerateToken_ManagerRole() {
        // Arrange
        String username = "manager";
        String role = "MANAGER";

        // Act
        String token = jwtService.generateToken(username, role);
        Map<String, Object> claims = jwtService.getAllClaimsFromToken(token);

        // Assert
        assertEquals(username, claims.get("sub"));
        assertNotNull(claims.get("authorities"));
    }

    @Test
    @DisplayName("Token vazio deve retornar false na validação")
    void testValidateToken_EmptyToken() {
        // Arrange
        String emptyToken = "";

        // Act
        boolean isValid = jwtService.validateToken(emptyToken);

        // Assert
        assertFalse(isValid);
    }

    @Test
    @DisplayName("Token null deve retornar false na validação")
    void testValidateToken_NullToken() {
        // Arrange
        String nullToken = null;

        // Act
        boolean isValid = jwtService.validateToken(nullToken);

        // Assert
        assertFalse(isValid);
    }
}