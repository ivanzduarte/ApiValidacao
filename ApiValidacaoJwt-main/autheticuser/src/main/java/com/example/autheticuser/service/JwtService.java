package com.example.autheticuser.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private long expirationTime;

    private SecretKey getSigningKey() {
        byte[] keyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Gera um token JWT com base nas informações do usuário.
     * 
     * @param username O nome de usuário (será o 'subject' do token).
     * @param role     A role (perfil) do usuário (adicionada como 'claim').
     * @return O token JWT assinado.
     */
    public String generateToken(String username, String role) {
        return Jwts.builder()
                .setSubject(username) // Define o nome de usuário como 'subject'
                .claim("authorities", List.of("ROLE_" + role)) // <- ESSA linha importa!
                .setIssuedAt(new Date()) // Define a data de emissão
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime)) // Define o tempo de expiração
                .signWith(getSigningKey(), SignatureAlgorithm.HS256) // Assina com a chave secreta usando o algoritmo
                                                                     // HS256
                .compact(); // Cria o token JWT
    }

    /**
     * Valida um token JWT.
     * 
     * @param token O token JWT a ser validado.
     * @return true se o token for válido e não expirado, false caso contrário.
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token);
            return true; // Se não lançar exceções, o token é válido
        } catch (ExpiredJwtException e) {
            System.err.println("Token expirado: " + e.getMessage());
        } catch (MalformedJwtException e) {
            System.err.println("Token malformado: " + e.getMessage());
        } catch (UnsupportedJwtException e) {
            System.err.println("Token não suportado: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Erro na validação do token: " + e.getMessage());
        }
        return false; // Se ocorrer uma exceção, o token é inválido
    }

    /**
     * Extrai o nome de usuário (subject) de um token JWT.
     * 
     * @param token O token JWT.
     * @return O username.
     */
    public String getUsernameFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject(); // Retorna o subject (nome de usuário)
    }

    /**
     * Extrai todas as claims de um token JWT.
     * 
     * @param token O token JWT.
     * @return Um mapa com as claims do token.
     */
    public Map<String, Object> getAllClaimsFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        return new HashMap<>(claims); // Retorna todas as claims do token em um Map
    }
}
