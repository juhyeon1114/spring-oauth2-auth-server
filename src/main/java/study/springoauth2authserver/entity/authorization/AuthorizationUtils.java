package study.springoauth2authserver.entity.authorization;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.function.Consumer;

import static org.springframework.security.oauth2.core.AuthorizationGrantType.*;

@Component
@RequiredArgsConstructor
public class AuthorizationUtils {

    private final RegisteredClientRepository registeredClientRepository;
    private final ObjectMapper objectMapper;

    public OAuth2Authorization toObject(Authorization entity) {
        RegisteredClient registeredClient = registeredClientRepository.findById(entity.getRegisteredClientId());
        if (registeredClient == null) {
            String message = "The RegisteredClient with id '" + entity.getRegisteredClientId() + "' was not found in the RegisteredClientRepository.";
            throw new DataRetrievalFailureException(message);
        }

        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(String.valueOf(entity.getId()))
                .principalName(entity.getPrincipalName())
                .authorizationGrantType(resolveAuthorizationGrantType(entity.getAuthorizationGrantType()))
                .authorizedScopes(entity.getAuthorizedScopes())
                .attributes(attributes -> attributes.putAll(entity.getAttributes()));
//                .attributes(attributes -> attributes.putAll(entity.getAttributes()));

        if (entity.getState() != null) {
            builder.attribute(OAuth2ParameterNames.STATE, entity.getState());
        }

        if (entity.getAuthorizationCodeValue() != null) {
            OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                    entity.getAuthorizationCodeValue(),
                    entity.getAuthorizationCodeIssuedAt(),
                    entity.getAuthorizationCodeExpiresAt());
            builder.token(authorizationCode, metadata -> metadata.putAll(entity.getAuthorizationCodeMetadata()));
        }

        if (entity.getAccessTokenValue() != null) {
            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    entity.getAccessTokenValue(),
                    entity.getAccessTokenIssuedAt(),
                    entity.getAccessTokenExpiresAt(),
                    entity.getAccessTokenScopes());
            builder.token(accessToken, metadata -> metadata.putAll(entity.getAccessTokenMetadata()));
        }

        if (entity.getRefreshTokenValue() != null) {
            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                    entity.getRefreshTokenValue(),
                    entity.getRefreshTokenIssuedAt(),
                    entity.getRefreshTokenExpiresAt());
            builder.token(refreshToken, metadata -> metadata.putAll(entity.getRefreshTokenMetadata()));
        }

        if (entity.getOidcIdTokenValue() != null) {
            OidcIdToken idToken = new OidcIdToken(
                    entity.getOidcIdTokenValue(),
                    entity.getOidcIdTokenIssuedAt(),
                    entity.getOidcIdTokenExpiresAt(),
                    entity.getOidcIdTokenClaims());
            builder.token(idToken, metadata -> metadata.putAll(entity.getOidcIdTokenMetadata()));
        }

        if (entity.getUserCodeValue() != null) {
            OAuth2UserCode userCode = new OAuth2UserCode(
                    entity.getUserCodeValue(),
                    entity.getUserCodeIssuedAt(),
                    entity.getUserCodeExpiresAt());
            builder.token(userCode, metadata -> metadata.putAll(entity.getUserCodeMetadata()));
        }

        if (entity.getDeviceCodeValue() != null) {
            OAuth2DeviceCode deviceCode = new OAuth2DeviceCode(
                    entity.getDeviceCodeValue(),
                    entity.getDeviceCodeIssuedAt(),
                    entity.getDeviceCodeExpiresAt());
            builder.token(deviceCode, metadata -> metadata.putAll(entity.getDeviceCodeMetadata()));
        }

        return builder.build();
    }

    public Authorization toEntity(OAuth2Authorization oAuth2Authorization) {
        Authorization entity = new Authorization();
        entity.setId(oAuth2Authorization.getId());
        entity.setRegisteredClientId(oAuth2Authorization.getRegisteredClientId());
        entity.setPrincipalName(oAuth2Authorization.getPrincipalName());
        entity.setAuthorizationGrantType(oAuth2Authorization.getAuthorizationGrantType().getValue());
        entity.setAuthorizedScopes(oAuth2Authorization.getAuthorizedScopes());
//        entity.setAttributes(writeMap(oAuth2Authorization.getAttributes()));
        entity.setAttributes(oAuth2Authorization.getAttributes());
        entity.setState(oAuth2Authorization.getAttribute(OAuth2ParameterNames.STATE));

        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = oAuth2Authorization.getToken(OAuth2AuthorizationCode.class);
        setTokenValues(authorizationCode, entity::setAuthorizationCodeValue, entity::setAuthorizationCodeIssuedAt, entity::setAuthorizationCodeExpiresAt, entity::setAuthorizationCodeMetadata);

        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = oAuth2Authorization.getToken(OAuth2AccessToken.class);
        setTokenValues(accessToken, entity::setAccessTokenValue, entity::setAccessTokenIssuedAt, entity::setAccessTokenExpiresAt, entity::setAccessTokenMetadata);
        if (accessToken != null && accessToken.getToken().getScopes() != null) {
            entity.setAccessTokenScopes(accessToken.getToken().getScopes());
        }

        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = oAuth2Authorization.getToken(OAuth2RefreshToken.class);
        setTokenValues(refreshToken, entity::setRefreshTokenValue, entity::setRefreshTokenIssuedAt, entity::setRefreshTokenExpiresAt, entity::setRefreshTokenMetadata);

        OAuth2Authorization.Token<OidcIdToken> oidcIdToken = oAuth2Authorization.getToken(OidcIdToken.class);
        setTokenValues(oidcIdToken, entity::setOidcIdTokenValue, entity::setOidcIdTokenIssuedAt, entity::setOidcIdTokenExpiresAt, entity::setOidcIdTokenMetadata);

        if (oidcIdToken != null) {
            entity.setOidcIdTokenClaims(oidcIdToken.getClaims());
        }

        OAuth2Authorization.Token<OAuth2UserCode> userCode = oAuth2Authorization.getToken(OAuth2UserCode.class);
        setTokenValues(userCode, entity::setUserCodeValue, entity::setUserCodeIssuedAt, entity::setUserCodeExpiresAt, entity::setUserCodeMetadata);

        OAuth2Authorization.Token<OAuth2DeviceCode> deviceCode = oAuth2Authorization.getToken(OAuth2DeviceCode.class);
        setTokenValues(deviceCode, entity::setDeviceCodeValue, entity::setDeviceCodeIssuedAt, entity::setDeviceCodeExpiresAt, entity::setDeviceCodeMetadata);

        return entity;
    }

    private Map<String, Object> parseMap(String data) {
        try {
            return objectMapper.readValue(data, new TypeReference<Map<String, Object>>() {
            });
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }

    private String writeMap(Map<String, Object> metadata) {
        try {
            return objectMapper.writeValueAsString(metadata);
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }

    private void setTokenValues(OAuth2Authorization.Token<?> token, Consumer<String> tokenValueConsumer, Consumer<Instant> issuedAtConsumer, Consumer<Instant> expiresAtConsumer, Consumer<Map<String, Object>> metadataConsumer) {
        if (token != null) {
            OAuth2Token oAuth2Token = token.getToken();
            tokenValueConsumer.accept(oAuth2Token.getTokenValue());
            issuedAtConsumer.accept(oAuth2Token.getIssuedAt());
            expiresAtConsumer.accept(oAuth2Token.getExpiresAt());
            metadataConsumer.accept(token.getMetadata());
        }
    }


    private static AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
        if (AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
            return AUTHORIZATION_CODE;
        } else if (CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
            return CLIENT_CREDENTIALS;
        } else if (REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
            return REFRESH_TOKEN;
        } else if (DEVICE_CODE.getValue().equals(authorizationGrantType)) {
            return DEVICE_CODE;
        }
        return new AuthorizationGrantType(authorizationGrantType);
    }

}
