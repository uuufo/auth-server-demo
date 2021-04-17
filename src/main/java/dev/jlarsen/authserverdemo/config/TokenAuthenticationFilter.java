package dev.jlarsen.authserverdemo.config;

import dev.jlarsen.authserverdemo.models.UserPrincipal;
import dev.jlarsen.authserverdemo.services.TokenService;
import lombok.SneakyThrows;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Inspects incoming requests for Authorization headers
 * If Bearer access token is present, process it for authentication, otherwise proceed down the filter chain
 */
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final TokenService tokenService;

    public TokenAuthenticationFilter(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @SneakyThrows
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) {

        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String authToken = authHeader.replace("Bearer ", "");
        UsernamePasswordAuthenticationToken token = createToken(authToken);
        SecurityContextHolder.getContext().setAuthentication(token);
        filterChain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken createToken(String authToken) throws Exception {
        UserPrincipal userPrincipal = tokenService.parseToken(authToken);
        List<GrantedAuthority> authorities =
                new ArrayList<>(Collections.singletonList(new SimpleGrantedAuthority("ROLE_CLIENT")));
        return new UsernamePasswordAuthenticationToken(userPrincipal, null, authorities);
    }
}