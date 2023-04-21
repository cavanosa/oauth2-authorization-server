package com.tutorial.authorizationserver.federated;

import com.tutorial.authorizationserver.entity.GoogleUser;
import com.tutorial.authorizationserver.repository.GoogleUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

@RequiredArgsConstructor
@Slf4j
public final class UserRepositoryOAuth2UserHandler implements Consumer<OAuth2User> {

    private final GoogleUserRepository googleUserRepository;

    @Override
    public void accept(OAuth2User user) {
        // Capture user in a local data store on first authentication
        if (!this.googleUserRepository.findByEmail(user.getName()).isPresent()) {
            GoogleUser googleUser = GoogleUser.fromOauth2User(user);
           log.info(googleUser.toString());
            this.googleUserRepository.save(googleUser);
        } else {
            log.info("bienvenido {}", user.getAttributes().get("given_name"));
        }
    }


}
