package com.example.autheticuser.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {
    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("API de Autenticação JWT Interna")
                .version("1.0.0")
                .description("API para autenticação, geração e validação interna de tokens JWT. Ideal para arquiteturas de microsserviços com autenticação centralizada.")
                .termsOfService("http://swagger.io/terms/")
                .contact(new Contact().name("Seu Nome/Equipe").email("seu.email@example.com"))
                .license(new License().name("Apache 2.0").url("http://www.apache.org/licenses/LICENSE-2.0.html")))
            .components(new Components()
                .addSecuritySchemes("bearerAuth", // Nome do esquema de segurança (usado com @SecurityRequirement)
                    new SecurityScheme()
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT")
                        .description("Token JWT para autenticação. Inclua no cabeçalho 'Authorization: Bearer <seu_token>'")));
    }
}
