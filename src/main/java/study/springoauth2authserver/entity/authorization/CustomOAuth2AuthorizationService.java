package study.springoauth2authserver.entity.authorization;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
@RequiredArgsConstructor
public class CustomOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final AuthorizationRepository authorizationRepository;
    private final AuthorizationUtils authorizationUtils;

    @Override
    public void save(OAuth2Authorization authorization) {
        Authorization entity = authorizationUtils.toEntity(authorization);
        authorizationRepository.save(entity);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        Authorization entity = authorizationUtils.toEntity(authorization);
        authorizationRepository.delete(entity);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        Authorization entity = authorizationRepository.findById(Long.valueOf(id)).orElseThrow();
        return authorizationUtils.toObject(entity);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Optional<Authorization> result;
        if (tokenType == null) {
            result = authorizationRepository.searchByToken(token);
        } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            result = authorizationRepository.findByState(token);
        } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            result = authorizationRepository.findByAuthorizationCodeValue(token);
        } else if (OAuth2ParameterNames.ACCESS_TOKEN.equals(tokenType.getValue())) {
            result = authorizationRepository.findByAccessTokenValue(token);
        } else if (OAuth2ParameterNames.REFRESH_TOKEN.equals(tokenType.getValue())) {
            result = authorizationRepository.findByRefreshTokenValue(token);
        } else if (OidcParameterNames.ID_TOKEN.equals(tokenType.getValue())) {
            result = authorizationRepository.findByOidcIdTokenValue(token);
        } else if (OAuth2ParameterNames.USER_CODE.equals(tokenType.getValue())) {
            result = authorizationRepository.findByUserCodeValue(token);
        } else if (OAuth2ParameterNames.DEVICE_CODE.equals(tokenType.getValue())) {
            result = authorizationRepository.findByDeviceCodeValue(token);
        } else {
            result = Optional.empty();
        }

        Authorization entity = result.orElseThrow();
        return authorizationUtils.toObject(entity);
    }
}
