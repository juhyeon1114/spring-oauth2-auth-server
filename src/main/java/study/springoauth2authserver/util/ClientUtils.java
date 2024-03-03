package study.springoauth2authserver.util;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import study.springoauth2authserver.entity.Client;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.springframework.security.oauth2.core.AuthorizationGrantType.*;
import static org.springframework.security.oauth2.core.ClientAuthenticationMethod.*;
import static org.springframework.util.StringUtils.collectionToCommaDelimitedString;
import static org.springframework.util.StringUtils.commaDelimitedListToSet;

@Component
@RequiredArgsConstructor
public class ClientUtils {

    public RegisteredClient toObject(Client client) {
        Set<String> clientAuthenticationMethods = commaDelimitedListToSet(client.getClientAuthenticationMethods());
        Set<String> authorizationGrantTypes = commaDelimitedListToSet(client.getAuthorizationGrantTypes());
        Set<String> redirectUris = commaDelimitedListToSet(client.getRedirectUris());
        Set<String> clientScopes = commaDelimitedListToSet(client.getScopes());
        Set<String> postLogoutUris = commaDelimitedListToSet(client.getPostLogoutRedirectUris());

        RegisteredClient.Builder registeredClient = RegisteredClient.withId(client.getId())
                .clientId(client.getClientId())
                .clientIdIssuedAt(client.getClientIdIssuedAt())
                .clientSecret(client.getClientSecret())
                .clientSecretExpiresAt(client.getClientSecretExpiresAt())
                .clientName(client.getClientName())
                .clientAuthenticationMethods(authenticationMethods -> clientAuthenticationMethods.forEach(authenticationMethod -> authenticationMethods.add(resolveClientAuthenticationMethod(authenticationMethod))))
                .authorizationGrantTypes((grantTypes) -> authorizationGrantTypes.forEach(grantType -> grantTypes.add(resolveAuthorizationGrantType(grantType))))
                .redirectUris((uris) -> uris.addAll(redirectUris))
                .postLogoutRedirectUris(uris -> uris.addAll(postLogoutUris))
                .scopes((scopes) -> scopes.addAll(clientScopes))
                .clientSettings(client.getClientSettings())
                .tokenSettings(client.getTokenSettings());

        return registeredClient.build();
    }

    public Client toEntity(RegisteredClient registeredClient) {
        List<String> clientAuthenticationMethods = new ArrayList<>(registeredClient.getClientAuthenticationMethods().size());
        registeredClient.getClientAuthenticationMethods().forEach(clientAuthenticationMethod -> clientAuthenticationMethods.add(clientAuthenticationMethod.getValue()));

        List<String> authorizationGrantTypes = new ArrayList<>(registeredClient.getAuthorizationGrantTypes().size());
        registeredClient.getAuthorizationGrantTypes().forEach(authorizationGrantType -> authorizationGrantTypes.add(authorizationGrantType.getValue()));

        Client entity = new Client();
        entity.setId(registeredClient.getId());
        entity.setClientId(registeredClient.getClientId());
        entity.setClientIdIssuedAt(registeredClient.getClientIdIssuedAt());
        entity.setClientSecret(registeredClient.getClientSecret());
        entity.setClientSecretExpiresAt(registeredClient.getClientSecretExpiresAt());
        entity.setClientName(registeredClient.getClientName());
        entity.setClientAuthenticationMethods(collectionToCommaDelimitedString(clientAuthenticationMethods));
        entity.setAuthorizationGrantTypes(collectionToCommaDelimitedString(authorizationGrantTypes));
        entity.setRedirectUris(collectionToCommaDelimitedString(registeredClient.getRedirectUris()));
        entity.setPostLogoutRedirectUris(collectionToCommaDelimitedString(registeredClient.getPostLogoutRedirectUris()));
        entity.setScopes(collectionToCommaDelimitedString(registeredClient.getScopes()));
        entity.setClientSettings(registeredClient.getClientSettings());
        entity.setTokenSettings(registeredClient.getTokenSettings());

        return entity;
    }

    private AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
        if (AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
            return AUTHORIZATION_CODE;
        } else if (CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
            return CLIENT_CREDENTIALS;
        } else if (REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
            return REFRESH_TOKEN;
        }
        return new AuthorizationGrantType(authorizationGrantType);
    }

    private ClientAuthenticationMethod resolveClientAuthenticationMethod(String clientAuthenticationMethod) {
        if (CLIENT_SECRET_BASIC.getValue().equals(clientAuthenticationMethod)) {
            return CLIENT_SECRET_BASIC;
        } else if (CLIENT_SECRET_POST.getValue().equals(clientAuthenticationMethod)) {
            return CLIENT_SECRET_POST;
        } else if (NONE.getValue().equals(clientAuthenticationMethod)) {
            return NONE;
        }
        return new ClientAuthenticationMethod(clientAuthenticationMethod);
    }

}
