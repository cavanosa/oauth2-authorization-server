package com.tutorial.authorizationserver.controller;

import com.tutorial.authorizationserver.twofactor.TwoFactorService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;

@Controller
@RequiredArgsConstructor
public class TwoFactorController {
    private final SecurityContextRepository securityContextRepository =
            new HttpSessionSecurityContextRepository();
    private final AuthenticationFailureHandler authenticationFailureHandler =
            new SimpleUrlAuthenticationFailureHandler("/twofactor?error");

    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final TwoFactorService twoFactorService;

    @GetMapping("/twofactor")
    public String twofactor(){
        return "twofactor";
    }

    @PostMapping("/twofactor")
    public void validateCode(@RequestParam("code")String code, HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        if(code.equals("abcd"))
            this.authenticationSuccessHandler.onAuthenticationSuccess(req, res, getAuthentication(req, res));
        else
            authenticationFailureHandler.onAuthenticationFailure(req, res, new BadCredentialsException("invalid code"));
    }

    private Authentication getAuthentication(HttpServletRequest req, HttpServletResponse res){
        Authentication authentication = twoFactorService.getAuthentication();
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);
        securityContextRepository.saveContext(securityContext, req, res);
        return authentication;
    }
}
