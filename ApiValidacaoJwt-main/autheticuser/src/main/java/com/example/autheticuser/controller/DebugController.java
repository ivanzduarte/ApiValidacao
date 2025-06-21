package com.example.autheticuser.controller;

import com.example.autheticuser.repository.Userrepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/dev")
public class DebugController {

    private final Userrepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DebugController(Userrepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // Lista todos os usuários do banco (inclui senha codificada apenas para depuração)
    @GetMapping("/usuarios")
    public List<Map<String, String>> listarUsuarios() {
        return userRepository.findAll().stream()
            .map(user -> Map.of(
                "username", user.getUsername(),
                "role", user.getRole(),
                "password", user.getPassword()
            ))
            .toList();
    }

    // Testa se a senha "123456" bate com a senha do usuário "admin"
    @GetMapping("/checar-senha")
    public Map<String, Object> checarSenha() {
        var user = userRepository.findByUsername("admin").orElseThrow();
        boolean senhaConfere = passwordEncoder.matches("123456", user.getPassword());

        return Map.of(
            "username", user.getUsername(),
            "senhaCodificada", user.getPassword(),
            "senhaDigitada", "123456",
            "resultadoDoMatch", senhaConfere
        );
    }
}
