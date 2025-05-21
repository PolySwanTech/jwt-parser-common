package org.pst.parser;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.security.interfaces.RSAPublicKey;
import java.util.Map;

public class JwtUtils {

    private final JwtDecoder jwtDecoder;

    public JwtUtils(RSAPublicKey publicKey) {
        this.jwtDecoder = NimbusJwtDecoder.withPublicKey(publicKey).build();
    }

    public Jwt decode(String token) {
        return jwtDecoder.decode(cleanToken(token));
    }

    public String extractUserId(String token) {
        return decode(token).getClaim("id");
    }

    public String extractUsername(String token) {
        return decode(token).getClaim("username");
    }

    public String extractEmail(String token) {
        return decode(token).getSubject();
    }

    public Map<String, Object> extractPermissions(String token) {
        return decode(token).getClaim("permissions");
    }


    private String cleanToken(String token) {
        return token.startsWith("Bearer ") ? token.substring(7) : token;
    }
}