package com.example.autheticuser.service;

import com.example.autheticuser.model.User;
import com.example.autheticuser.repository.Userrepository;
import com.example.autheticuser.repository.Userrepository;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@SuppressWarnings("unused")
@Service
public class AuthService {

    private final Userrepository Userrepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService; // Injeta o serviço de JWT

    public AuthService(Userrepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.Userrepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    /**
     * Autentica um usuário e, se bem-sucedido, gera e retorna um token JWT.
     * @param username Nome de usuário.
     * @param password Senha em texto claro.
     * @return O token JWT.
     * @throws BadCredentialsException Se as credenciais forem inválidas.
     */
    public String authenticateUserAndGenerateToken(String username, String password) {
        Optional<User> userOptional = Userrepository.findByUsername(username);

        if (userOptional.isEmpty()) {
            throw new BadCredentialsException("Credenciais inválidas: Usuário não encontrado.");
        }

        User user = userOptional.get();

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new BadCredentialsException("Credenciais inválidas: Senha incorreta.");
        }

        return jwtService.generateToken(user.getUsername(), user.getRole());
    }
}

