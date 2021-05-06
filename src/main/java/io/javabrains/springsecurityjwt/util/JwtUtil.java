package io.javabrains.springsecurityjwt.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtUtil {

    private PrivateKey getPrivateKey() throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, IOException {
        return getKeyPair().getPrivate();
    }

    private PublicKey getPublicKey() throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, IOException {
        return getKeyPair().getPublic();
    }

    private KeyPair getKeyPair() throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, IOException {
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(this.getClass().getClassLoader().getResourceAsStream("idcapp-jwt-signing-selfsigned.p12"), "".toCharArray());
        Key key = keystore.getKey("1", "".toCharArray());
        if (key instanceof PrivateKey) {
            java.security.cert.Certificate cert = keystore.getCertificate("1");
            PublicKey publicKey = cert.getPublicKey();
            return new KeyPair(publicKey, (PrivateKey) key);
        } else {
            throw new KeyStoreException ("Private key not found in keystore");
        }
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        PublicKey publicKey;
        try {
            publicKey = getPublicKey();
        } catch (Exception e) {
            System.out.println("Error message is " + e.getMessage());
            e.printStackTrace();
            return null;
        }
        return Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails.getUsername());
    }

    private String createToken(Map<String, Object> claims, String subject) {

        PrivateKey privateKey;
        try {
            privateKey = getPrivateKey();
        } catch (Exception e) {
            System.out.println("Error message is " + e.getMessage());
            e.printStackTrace();
            return "private key error";
        }
        Instant now = Instant.now();
        return Jwts.builder()
                .setHeaderParam("alg", "RS256")
                .setHeaderParam("typ", "JWT")
                .setHeaderParam("x5t", "a6d1abc9a008da3a6ff0eaeba0931cc5329b0a7b")
                .setHeaderParam("x5u", "https://pki.ing.net")
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(Date.from(now.plus(30, ChronoUnit.MINUTES)))
                .signWith(SignatureAlgorithm.RS256, privateKey)
                .compact();

    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}