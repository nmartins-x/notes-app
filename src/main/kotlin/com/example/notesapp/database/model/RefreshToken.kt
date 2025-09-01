package com.example.notesapp.database.model

import org.bson.types.ObjectId
import org.springframework.data.mongodb.core.index.Indexed
import org.springframework.data.mongodb.core.mapping.Document
import java.time.Instant

@Document("refresh_tokens")
data class RefreshToken(
    private val userId: ObjectId,
    private val hashedToken: String,
    private val createdAt: Instant = Instant.now(),
    @Indexed(expireAfter = "0s") private val expiresAt: Instant // MongoDB apaga este refresh token automaticamente quando chega data do expiresAt
)
