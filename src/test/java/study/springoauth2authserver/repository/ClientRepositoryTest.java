package study.springoauth2authserver.repository;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import study.springoauth2authserver.entity.client.Client;
import study.springoauth2authserver.entity.client.ClientRepository;
import study.springoauth2authserver.entity.client.ClientUtils;

import java.util.UUID;


@Slf4j
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ClientRepositoryTest {

    @Autowired
    ClientRepository clientRepository;

    @Autowired
    ClientUtils clientUtils;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Test
    @DisplayName("createClient")
    public void createClient() throws Exception {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientName("Your client name")
                .clientId("your-client")
                .clientSecret(passwordEncoder.encode("your-secret"))
                .clientAuthenticationMethods(methods -> {
                    methods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
                })
                .authorizationGrantTypes(types -> {
                    types.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                    types.add(AuthorizationGrantType.REFRESH_TOKEN);
                })
                .redirectUris(uri -> {
                    uri.add("http://localhost:3000");
                })
                .postLogoutRedirectUris(uri -> {
                    uri.add("http://localhost:3000");
                })
                .scopes(scope -> {
                    scope.add(OidcScopes.OPENID);
                    scope.add(OidcScopes.PROFILE);
                })
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .build();

        Client entity = clientUtils.toEntity(registeredClient);
        log.info(entity.getClientId());

        Client saved = clientRepository.saveAndFlush(entity);

        Client found = clientRepository.findById(saved.getId()).orElseThrow();
        RegisteredClient parsed = clientUtils.toObject(found);
        log.info(parsed.getClientId());
    }

}