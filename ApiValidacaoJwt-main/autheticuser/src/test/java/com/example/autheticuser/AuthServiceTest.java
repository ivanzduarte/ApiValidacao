package com.example.autheticuser;

import com.example.autheticuser.model.User;
import com.example.autheticuser.repository.Userrepository;
import com.example.autheticuser.service.AuthService;
import com.example.autheticuser.service.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("Testes Unitários - AuthService")
class AuthServiceTest {

    @Mock
    private Userrepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @InjectMocks
    private AuthService authService;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = new User(1L, "testuser", "encodedPassword", "USER");
    }

    @Test
    @DisplayName("Autenticação bem-sucedida deve gerar token")
    void testAuthenticateUserAndGenerateToken_Success() {
        // Arrange
        String username = "testuser";
        String password = "password123";
        String expectedToken = "jwt.token.here";

        when(userRepository.findByUsername(username)).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(password, testUser.getPassword())).thenReturn(true);
        when(jwtService.generateToken(username, testUser.getRole())).thenReturn(expectedToken);

        // Act
        String result = authService.authenticateUserAndGenerateToken(username, password);

        // Assert
        assertEquals(expectedToken, result);
        verify(userRepository).findByUsername(username);
        verify(passwordEncoder).matches(password, testUser.getPassword());
        verify(jwtService).generateToken(username, testUser.getRole());
    }

    @Test
    @DisplayName("Usuário não encontrado deve lançar BadCredentialsException")
    void testAuthenticateUserAndGenerateToken_UserNotFound() {
        // Arrange
        String username = "nonexistent";
        String password = "password123";

        when(userRepository.findByUsername(username)).thenReturn(Optional.empty());

        // Act & Assert
        BadCredentialsException exception = assertThrows(BadCredentialsException.class, () -> {
            authService.authenticateUserAndGenerateToken(username, password);
        });

        assertEquals("Credenciais inválidas: Usuário não encontrado.", exception.getMessage());
        verify(userRepository).findByUsername(username);
        verify(passwordEncoder, never()).matches(anyString(), anyString());
        verify(jwtService, never()).generateToken(anyString(), anyString());
    }

    @Test
    @DisplayName("Senha incorreta deve lançar BadCredentialsException")
    void testAuthenticateUserAndGenerateToken_WrongPassword() {
        // Arrange
        String username = "testuser";
        String password = "wrongpassword";

        when(userRepository.findByUsername(username)).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(password, testUser.getPassword())).thenReturn(false);

        // Act & Assert
        BadCredentialsException exception = assertThrows(BadCredentialsException.class, () -> {
            authService.authenticateUserAndGenerateToken(username, password);
        });

        assertEquals("Credenciais inválidas: Senha incorreta.", exception.getMessage());
        verify(userRepository).findByUsername(username);
        verify(passwordEncoder).matches(password, testUser.getPassword());
        verify(jwtService, never()).generateToken(anyString(), anyString());
    }

    @Test
    @DisplayName("Autenticação com usuário admin deve gerar token com role admin")
    void testAuthenticateUserAndGenerateToken_AdminUser() {
        // Arrange
        User adminUser = new User(2L, "admin", "encodedPassword", "admin");
        String username = "admin";
        String password = "adminpass";
        String expectedToken = "admin.jwt.token";

        when(userRepository.findByUsername(username)).thenReturn(Optional.of(adminUser));
        when(passwordEncoder.matches(password, adminUser.getPassword())).thenReturn(true);
        when(jwtService.generateToken(username, "admin")).thenReturn(expectedToken);

        // Act
        String result = authService.authenticateUserAndGenerateToken(username, password);

        // Assert
        assertEquals(expectedToken, result);
        verify(jwtService).generateToken(username, "admin");
    }

    @Test
    @DisplayName("Autenticação com usuário manager deve gerar token com role MANAGER")
    void testAuthenticateUserAndGenerateToken_ManagerUser() {
        // Arrange
        User managerUser = new User(3L, "manager", "encodedPassword", "MANAGER");
        String username = "manager";
        String password = "managerpass";
        String expectedToken = "manager.jwt.token";

        when(userRepository.findByUsername(username)).thenReturn(Optional.of(managerUser));
        when(passwordEncoder.matches(password, managerUser.getPassword())).thenReturn(true);
        when(jwtService.generateToken(username, "MANAGER")).thenReturn(expectedToken);

        // Act
        String result = authService.authenticateUserAndGenerateToken(username, password);

        // Assert
        assertEquals(expectedToken, result);
        verify(jwtService).generateToken(username, "MANAGER");
    }
}