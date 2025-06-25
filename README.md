# Spring Boot JWT Authentication System

This project implements user login and JWT-based authentication and authorization using Spring Boot. It is based on the YouTube tutorial series: [Java Spring Boot JWT Authentication](https://www.youtube.com/watch?v=VVn9OG9nfH0).

## Features

- Username and password login endpoint (`/api/login`)
- JWT Access Token and Refresh Token generation and verification
- Role-based access control
- Custom authentication filter (`CustomAuthenticationFilter`)
- Custom authorization filter (`CustomAuthorizationFilter`)
- Stateless session management
- JWT signed with HMAC256 algorithm

## Technology Stack

- Java 17+
- Spring Boot 3.x
- Spring Security
- JSON Web Tokens (JWT)
- Maven
- Lombok
- Postgresql
- Postman (for API testing)

## Project Structure
src/

├── api/ # Controller layer (User APIs)

├── domain/ # Entity classes (User, Role)

├── filter/ # Custom Authentication & Authorization filters

├── repo/ # Data access layer (Spring Data JPA)

├── security/ # Security config & JWT utilities

├── service/ # Business logic layer

└── Application.java # Spring Boot application starter

## The application will start on:
http://localhost:9090

## Example API usage
### Login to get tokens
POST /api/login

Content-Type: application/x-www-form-urlencoded

Body: username=arnold&password=1234

### Refresh access token
GET /api/token/refresh

Headers: Authorization: Bearer <refresh_token>

### Get user info (requires authorization)
GET /api/user

Headers: Authorization: Bearer <access_token>

## Security Details
Authentication logic overridden via UsernamePasswordAuthenticationFilter

Authorization handled with OncePerRequestFilter validating JWT tokens

Tokens signed using HMAC256 algorithm

CSRF disabled and stateless session management enabled
