package com.example.autheticuser;

import com.example.autheticuser.repository.Userrepository;
import com.example.autheticuser.service.AuthService;
import com.example.autheticuser.service.JwtService;
import com.example.autheticuser.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.example.autheticuser.model.LoginRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DisplayName("Testes de Integração - Autenticação e Autorização")
class AuthIntegrationTests {

        @Autowired
        private MockMvc mockMvc;

        @Autowired
        private AuthService authService;

        @Autowired
        private JwtService jwtService;

        @Autowired
        private Userrepository userRepository;

        @Autowired
        private PasswordEncoder passwordEncoder;

        @Autowired
        private ObjectMapper objectMapper;

        @BeforeEach
        void setup() {
                // Limpa o banco antes de cada teste
                userRepository.deleteAll();

                // Cria usuário admin
                User admin = new User(null, "admin", passwordEncoder.encode("123456"), "admin");
                userRepository.save(admin);

                // Cria usuário regular
                User regularUser = new User(null, "user", passwordEncoder.encode("password"), "USER");
                userRepository.save(regularUser);

                // Cria usuário com role diferente
                User manager = new User(null, "manager", passwordEncoder.encode("manager123"), "MANAGER");
                userRepository.save(manager);
        }

        @Test
        @DisplayName("Login bem-sucedido deve retornar token JWT válido")
        void testLoginSuccess() throws Exception {
                LoginRequest loginRequest = new LoginRequest();
                loginRequest.setUsername("admin");
                loginRequest.setPassword("123456");

                MvcResult result = mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(loginRequest)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.token_type", is("Bearer")))
                                .andExpect(jsonPath("$.access_token", notNullValue()))
                                .andReturn();

                String responseContent = result.getResponse().getContentAsString();
                assertTrue(responseContent.contains("access_token"));

                // Extrai o token da resposta
                String token = objectMapper.readTree(responseContent).get("access_token").asText();

                // Valida se o token é válido
                assertTrue(jwtService.validateToken(token));
                assertEquals("admin", jwtService.getUsernameFromToken(token));
        }

        @Test
        @DisplayName("Login com senha incorreta deve retornar 401")
        void testLoginFailureInvalidPassword() throws Exception {
                LoginRequest loginRequest = new LoginRequest();
                loginRequest.setUsername("admin");
                loginRequest.setPassword("senhaErrada");

                mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(loginRequest)))
                                .andExpect(status().isUnauthorized())
                                .andExpect(jsonPath("$.error", containsString("Credenciais inválidas")));
        }

        @Test
        @DisplayName("Login com usuário inexistente deve retornar 401")
        void testLoginFailureUserNotFound() throws Exception {
                LoginRequest loginRequest = new LoginRequest();
                loginRequest.setUsername("usuarioInexistente");
                loginRequest.setPassword("123456");

                mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(loginRequest)))
                                .andExpect(status().isUnauthorized())
                                .andExpect(jsonPath("$.error", containsString("Credenciais inválidas")));
        }

        @Test
        @DisplayName("Endpoint protegido sem token deve retornar 401")
        void testProtectedEndpointAccessDeniedWithoutToken() throws Exception {
                mockMvc.perform(get("/api/hello"))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Endpoint protegido com token válido deve permitir acesso")
        void testProtectedEndpointAccessWithValidToken() throws Exception {
                // Faz login para obter token
                LoginRequest loginRequest = new LoginRequest();
                loginRequest.setUsername("user");
                loginRequest.setPassword("password");
                MvcResult loginResult = mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(loginRequest)))
                                .andExpect(status().isOk())
                                .andReturn();

                String token = objectMapper.readTree(loginResult.getResponse().getContentAsString())
                                .get("access_token").asText();

                // Acessa endpoint protegido com token
                mockMvc.perform(get("/api/hello")
                                .header("Authorization", "Bearer " + token))
                                .andExpect(status().isOk())
                                .andExpect(content().string("Olá! Você acessou um endpoint protegido com sucesso!"));
        }

        @Test
        @DisplayName("Endpoint admin com token de admin deve permitir acesso")
        void testProtectedAdminEndpointAccessWithAdminToken() throws Exception {
                // Faz login como admin
                LoginRequest loginRequest = new LoginRequest();
                loginRequest.setUsername("admin");
                loginRequest.setPassword("123456");
                MvcResult loginResult = mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(loginRequest)))
                                .andExpect(status().isOk())
                                .andReturn();

                String token = objectMapper.readTree(loginResult.getResponse().getContentAsString())
                                .get("access_token").asText();

                // Acessa endpoint admin com token de admin
                mockMvc.perform(get("/api/admin")
                                .header("Authorization", "Bearer " + token))
                                .andExpect(status().isOk())
                                .andExpect(content().string("Bem-vindo, Administrador! Este é um recurso restrito."));
        }

        @Test
        @DisplayName("Endpoint admin com token de usuário comum deve retornar 403")
        void testProtectedAdminEndpointAccessDeniedWithUserToken() throws Exception {
                // Faz login como usuário comum
                LoginRequest loginRequest = new LoginRequest();
                loginRequest.setUsername("user");
                loginRequest.setPassword("password");
                MvcResult loginResult = mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(loginRequest)))
                                .andExpect(status().isOk())
                                .andReturn();

                String token = objectMapper.readTree(loginResult.getResponse().getContentAsString())
                                .get("access_token").asText();

                // Tenta acessar endpoint admin com token de usuário comum
                mockMvc.perform(get("/api/admin")
                                .header("Authorization", "Bearer " + token))
                                .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("Endpoint admin com token de manager deve retornar 403")
        void testProtectedAdminEndpointAccessDeniedWithManagerToken() throws Exception {
                // Faz login como manager
                LoginRequest loginRequest = new LoginRequest();
                loginRequest.setUsername("manager");
                loginRequest.setPassword("manager123");
                MvcResult loginResult = mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(loginRequest)))
                                .andExpect(status().isOk())
                                .andReturn();

                String token = objectMapper.readTree(loginResult.getResponse().getContentAsString())
                                .get("access_token").asText();

                // Tenta acessar endpoint admin com token de manager
                mockMvc.perform(get("/api/admin")
                                .header("Authorization", "Bearer " + token))
                                .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("Validação de token válido deve retornar sucesso")
        void testValidateValidToken() throws Exception {
                // Faz login para obter token
                LoginRequest loginRequest = new LoginRequest();
                loginRequest.setUsername("user");
                loginRequest.setPassword("password");
                MvcResult loginResult = mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(loginRequest)))
                                .andExpect(status().isOk())
                                .andReturn();

                String token = objectMapper.readTree(loginResult.getResponse().getContentAsString())
                                .get("access_token").asText();

                // Valida o token
                mockMvc.perform(post("/auth/validate")
                                .param("token", token))
                                .andExpect(status().isOk())
                                .andExpect(content().string(containsString("Token válido")));
        }

        @Test
        @DisplayName("Validação de token inválido deve retornar erro")
        void testValidateInvalidToken() throws Exception {
                mockMvc.perform(post("/auth/validate")
                                .param("token", "token.invalido.qualquer"))
                                .andExpect(status().isUnauthorized())
                                .andExpect(content().string("Token inválido ou expirado."));
        }

        @Test
        @DisplayName("Token com formato Bearer incorreto deve retornar 401")
        void testInvalidBearerFormat() throws Exception {
                mockMvc.perform(get("/api/hello")
                                .header("Authorization", "InvalidFormat token123"))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Token Bearer vazio deve retornar 401")
        void testEmptyBearerToken() throws Exception {
                mockMvc.perform(get("/api/hello")
                                .header("Authorization", "Bearer "))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Múltiplos logins devem gerar tokens diferentes")
        void testMultipleLoginsGenerateDifferentTokens() throws Exception {
                LoginRequest loginRequest = new LoginRequest();
                loginRequest.setUsername("user");
                loginRequest.setPassword("password");

                // Primeiro login
                MvcResult result1 = mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(loginRequest)))
                                .andExpect(status().isOk())
                                .andReturn();

                String token1 = objectMapper.readTree(result1.getResponse().getContentAsString())
                                .get("access_token").asText();

                // Segundo login
                MvcResult result2 = mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(loginRequest)))
                                .andExpect(status().isOk())
                                .andReturn();

                String token2 = objectMapper.readTree(result2.getResponse().getContentAsString())
                                .get("access_token").asText();

                // Tokens devem ser diferentes (devido ao timestamp)
                assertNotEquals(token1, token2);

                // Ambos devem ser válidos
                assertTrue(jwtService.validateToken(token1));
                assertTrue(jwtService.validateToken(token2));
        }
}