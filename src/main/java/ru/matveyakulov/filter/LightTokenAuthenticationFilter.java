package ru.matveyakulov.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.matveyakulov.dto.LightToken;
import ru.matveyakulov.dto.LightTokenAuthentication;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class LightTokenAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTH_HEADER = "X-Auth-Token";
    private static final String AUTHORIZATION = "Authorization";

    @Value("${application.authentication.hmac-secret:qweqweqeqweqweqweqweqweqwqwqeqweqweqweqweqwe}")
    private String hmacSecret;

    @Value("${application.authentication.token-expired:1000}")
    private Long maxTokenAgeSeconds;

    @Value("${application.authentication.service-name:demo1}")
    private String serviceName;

    private List<String> allowedServices = List.of("demo1", "demo2");

    private final ConcurrentHashMap<String, Long> recentNonces = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String lightWeightToken = request.getHeader(AUTH_HEADER);
        String jwtToken = request.getHeader(AUTHORIZATION);
        if (!StringUtils.hasLength(lightWeightToken)) {
            if (!StringUtils.hasLength(jwtToken)) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing token");
            }
            Authentication auth = new LightTokenAuthentication("ADMIN", serviceName);
            SecurityContextHolder.getContext().setAuthentication(auth);
            filterChain.doFilter(request, response);
            return;
        }

        try {
            LightToken lightToken = LightToken.parse(lightWeightToken);
            verifyToken(lightToken);
            Authentication auth = new LightTokenAuthentication(lightToken.getUsername(), lightToken.getService());
            SecurityContextHolder.getContext().setAuthentication(auth);
            filterChain.doFilter(request, response);

        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token: " + e.getMessage());
        }
    }

    private void verifyToken(LightToken token) throws Exception {
        long now = Instant.now().getEpochSecond();

        if (!allowedServices.contains(token.getService())) {
            throw new SecurityException("Service not allowed");
        }
        if (now - token.getTimestamp() > maxTokenAgeSeconds) {
            throw new SecurityException("Token expired");
        }

        if (recentNonces.containsKey(token.getNonce())) {
            throw new SecurityException("Replay detected: nonce already used");
        }

        String payload = "%s|%d|%s|%s".formatted(
                        token.getService(), token.getTimestamp(), token.getUsername(), token.getNonce());
        String expectedSig = hmacSha256(payload, hmacSecret);

        if (!expectedSig.equals(token.getSignature())) {
            throw new SecurityException("Signature mismatch");
        }

        recentNonces.put(token.getNonce(), now);
        // Очистка старых nonces (по TTL) может выполняться периодически
    }

    @Scheduled(fixedDelay = 10000)
    public void cleanExpiredNonces() {
        long now = Instant.now().getEpochSecond();
        recentNonces.entrySet().removeIf(entry -> (now - entry.getValue()) > maxTokenAgeSeconds);
    }

    private String hmacSha256(String data, String key) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        hmac.init(secretKey);
        byte[] hash = hmac.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }

}