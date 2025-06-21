# AutheticUser - API de Autenticação com JWT

Esta aplicação, desenvolvida com **Spring Boot**, fornece autenticação via **JWT (JSON Web Token)**. A seguir, veja como executar a aplicação, acessar ferramentas úteis e rodar testes de carga.

---

## ✅ Requisitos

- Java 17 ou superior  
- Maven instalado  
- JMeter (para testes de carga)  

---

## 🚀 Como rodar a aplicação

1. Clone o repositório:

```bash
git clone https://github.com/seuusuario/autheticuser.git
cd autheticuser
Compile o projeto:

bash
mvn clean install
Execute o projeto:

bash
mvn spring-boot:run
A aplicação estará disponível em: http://localhost:8080

📄 Acessando o Swagger
A documentação interativa da API está disponível em:

👉 http://localhost:8080/swagger-ui/index.html#/Autenticação/login

Para testar o login via Swagger:

Acesse POST /auth/login

Use o corpo da requisição:

json
{
  "username": "admin",
  "password": "123456"
}
🗃️ Acessando o Console H2
Para acessar o H2 Console, vá até:

👉 http://localhost:8080/h2-console

Credenciais:

JDBC URL: jdbc:h2:mem:testdb

Usuário: gustavo

Senha: 123456

🧪 Teste de carga com JMeter
Etapas no JMeter
Criar novo plano de teste: Vá em File > New

Adicionar Thread Group: Clique direito em Test Plan > Add > Threads (Users) > Thread Group

Number of Threads (users): 200

Ramp-up period (seconds): 20

Loop Count: 10 (ou marque "Forever" para requisições contínuas)

Adicionar HTTP Request: Clique direito no Thread Group > Add > Sampler > HTTP Request

Name: Login Request

Protocol: http

Server Name or IP: localhost

Port Number: 8080

Method: POST

Path: /auth/login

Configurar o corpo da requisição (Body Data):

json
{
  "username": "admin",
  "password": "123456"
}
Adicionar HTTP Header Manager: Clique direito em Login Request > Add > Config Element > HTTP Header Manager Configure:

Name: Content-Type

Value: application/json

Visualizar resultados: Clique direito em Thread Group > Add > Listener > View Results Tree
