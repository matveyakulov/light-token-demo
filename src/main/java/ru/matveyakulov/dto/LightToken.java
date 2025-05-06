package ru.matveyakulov.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

import java.util.Base64;

@Builder
@Getter
@AllArgsConstructor
public class LightToken {

    private final String service;
    private final long timestamp;
    private final String username;
    private final String nonce;
    private final String signature;

    public static LightToken parse(String token) {
        String decoded = new String(Base64.getDecoder().decode(token));
        String[] parts = decoded.split("\\|");
        if (parts.length != 5) throw new IllegalArgumentException("Invalid token format");
        return LightToken.builder()
                .service(parts[0])
                .timestamp(Long.parseLong(parts[1]))
                .username(parts[2])
                .nonce(parts[3])
                .signature(parts[4])
                .build();
    }
}