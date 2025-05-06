package ru.matveyakulov.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Collections;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String SECRET_KEY = "qweasdqweqwasdqweqweqwesdasdrqweqwsadaqweq";
    private static final Key SIGNING_KEY = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
    private static final String AUTHORIZATION = "Authorization";
    private static final String AUTH_HEADER = "X-Auth-Token";
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtParser jwtParser = Jwts.parser()
            .setSigningKey(SIGNING_KEY)
            .build();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String lightWeightToken = request.getHeader(AUTH_HEADER);
        String bearerToken = request.getHeader(AUTHORIZATION);
        if (!StringUtils.hasLength(lightWeightToken)) {
            if (!StringUtils.hasLength(bearerToken)) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing token");
            }
            filterChain.doFilter(request, response);
            return;
        }
        if (bearerToken == null || !bearerToken.startsWith(BEARER_PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = bearerToken.substring(BEARER_PREFIX.length());

        try {
            Claims claims = jwtParser.parseSignedClaims(token).getPayload();

            String username = claims.get("username", String.class);
            String service = claims.get("svc", String.class);

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(username, null, Collections.emptyList());

            authentication.setDetails(service);
            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (MalformedJwtException | SignatureException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Invalid JWT: " + e.getMessage());
            return;
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("JWT validation error");
            return;
        }

        filterChain.doFilter(request, response);
    }
}