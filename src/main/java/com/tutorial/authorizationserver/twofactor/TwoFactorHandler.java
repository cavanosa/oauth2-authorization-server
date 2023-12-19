package com.tutorial.authorizationserver.twofactor;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

import java.io.IOException;

public class TwoFactorHandler implements AuthenticationSuccessHandler {
    private final SecurityContextRepository securityContextRepository =
            new HttpSessionSecurityContextRepository();
    private final Authentication auth_token = new AnonymousAuthenticationToken(
            "anonymous", "anonymous", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS", "ROLE_TWO_F")
    );

    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final TwoFactorService twoFactorService;

    public TwoFactorHandler(TwoFactorService twoFactorService) {
        SimpleUrlAuthenticationSuccessHandler authenticationSuccessHandler =
                new SimpleUrlAuthenticationSuccessHandler("/twofactor");
        authenticationSuccessHandler.setAlwaysUseDefaultTargetUrl(true);
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        this.twoFactorService = twoFactorService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        twoFactorService.setAuthentication(authentication);
        setAuthentication(request, response);
        this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, auth_token);
    }

    private void setAuthentication(HttpServletRequest request, HttpServletResponse response){
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(auth_token);
        SecurityContextHolder.setContext(securityContext);
        securityContextRepository.saveContext(securityContext, request, response);
    }
}
