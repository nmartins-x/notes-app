package com.example.demo.security

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpStatusCode
import org.springframework.stereotype.Service
import org.springframework.web.server.ResponseStatusException
import java.util.Base64
import java.util.Date

@Service
class JwtService (
    @Value("\${jwt.secret}") private val jwtSecret: String
) {
    private final val CLAIM_TYPE_ACCESS = "access"
    private final val CLAIM_TYPE_REFRESH = "refresh"

    private val secretKey = Keys.hmacShaKeyFor(
        Base64
            .getDecoder()
            .decode(jwtSecret)
    )

    private val accessTokenValidityMs = 15L * 60L * 1000L
    val refreshTokenValidityMs = 30L * 24L * 60L * 60 * 1000L

    private fun generateToken(
        userId: String,
        type: String,
        expiry: Long
    ): String {
        val now = Date()
        val expiryDate = Date(now.time + expiry)
        return Jwts.builder()
            .subject(userId)
            .claim("type", type)
            .issuedAt(now)
            .expiration(expiryDate)
            .signWith(secretKey, Jwts.SIG.HS256)
            .compact()
    }

    // token de pouca duracao usado para api requests
    fun generateAccessToken(userId: String): String {
        return generateToken(userId, CLAIM_TYPE_ACCESS, accessTokenValidityMs)
    }

    // token de longa duracao usado para obter um novo access token
    fun generateRefreshToken(userId: String): String {
        return generateToken(userId, CLAIM_TYPE_REFRESH, refreshTokenValidityMs)
    }

    fun validateAccessToken(token: String): Boolean {
        val claims = parseAllClaims(token) ?: return false
        val tokenType = claims["type"] as? String ?: return false
        return tokenType == CLAIM_TYPE_ACCESS
    }

    fun validateRefreshToken(token: String): Boolean {
        val claims = parseAllClaims(token) ?: return false
        val tokenType = claims["type"] as? String ?: return false
        return tokenType == CLAIM_TYPE_REFRESH
    }

    // Authorization: Bearer <token>
    fun getUserIdFromToken(token: String): String {
        val claims = parseAllClaims(token) ?: throw ResponseStatusException(
            HttpStatusCode.valueOf(401),
            "Invalid refresh token"
        )

        return claims.subject
    }

    private fun parseAllClaims(token: String): Claims? {
        val rawToken = if (token.startsWith("Bearer ")) token.removePrefix("Bearer ") else token
        return try {
            Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(rawToken)
                .payload
        } catch (e: Exception) {
            null
        }
    }
}