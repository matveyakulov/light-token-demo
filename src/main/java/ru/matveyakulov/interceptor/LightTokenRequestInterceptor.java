package ru.matveyakulov.interceptor;

import feign.RequestInterceptor;
import feign.RequestTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.UUID;

@Component
public class LightTokenRequestInterceptor implements RequestInterceptor {

    private static final String SERVICE_NAME = "svc-demo";
    private static final String HMAC_SECRET = "very-secret-key";

    @Override
    public void apply(RequestTemplate template) {
        String token = generateLightToken();
        template.header("X-Auth-Token", token);
    }

    private String generateLightToken() {
        String timestamp = String.valueOf(System.currentTimeMillis() / 1000);
        String nonce = UUID.randomUUID().toString();
        String username = getCurrentUsername();

        String payload = String.join("|", SERVICE_NAME, timestamp, username, nonce);
        String signature = hmacSha256(payload, HMAC_SECRET);

        String fullToken = payload + "|" + signature;
        return Base64.getEncoder().encodeToString(fullToken.getBytes());
    }

    private String hmacSha256(String data, String key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "HmacSHA256");
            mac.init(secretKey);
            return Base64.getEncoder().encodeToString(mac.doFinal(data.getBytes()));
        } catch (Exception e) {
            throw new RuntimeException("Ошибка при генерации подписи токена", e);
        }
    }

    private String getCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication instanceof UsernamePasswordAuthenticationToken token && authentication.isAuthenticated()) {
            Object principal = token.getPrincipal();

            if (principal instanceof org.springframework.security.core.userdetails.UserDetails userDetails) {
                return userDetails.getUsername();
            } else if (principal instanceof String str) {
                return str;
            }
        }

        return "anonymous";
    }
}
