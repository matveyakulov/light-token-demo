package ru.matveyakulov.dto;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;

@Getter
public class LightTokenAuthentication extends AbstractAuthenticationToken {

    private final String username;
    private final String service;

    public LightTokenAuthentication(String username, String service) {
        super(Collections.singletonList(new SimpleGrantedAuthority("ROLE_SERVICE")));
        this.username = username;
        this.service = service;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return service;
    }

    @Override
    public Object getPrincipal() {
        return username;
    }
}