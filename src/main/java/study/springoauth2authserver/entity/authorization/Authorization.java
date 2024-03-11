package study.springoauth2authserver.entity.authorization;

import com.vladmihalcea.hibernate.type.json.JsonBinaryType;
import com.vladmihalcea.hibernate.type.json.JsonType;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.Type;
import org.hibernate.type.AnyType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.security.Principal;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

@Getter
@Setter
@Entity
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Authorization {

    @Id
    private String id;
    private String registeredClientId;
    private String principalName;
    private String authorizationGrantType;
    @Type(JsonType.class)
    @Column(columnDefinition = "json")
    private Set<String> authorizedScopes;

//    @Type(JsonBinaryType.class)
    @Type(JsonType.class)
//    @Column(columnDefinition = "json")
    @Column(columnDefinition = "json")
    private Map<String, Object> attributes;
//    @Column(length = 4000)
//    private String attributes;
    @Column(length = 500)
    private String state;

    @Column(length = 1000)
    private String authorizationCodeValue;
    private Instant authorizationCodeIssuedAt;
    private Instant authorizationCodeExpiresAt;
    @Type(JsonType.class)
    @Column(columnDefinition = "json")
    private Map<String, Object> authorizationCodeMetadata;

    @Column(length = 1000)
    private String accessTokenValue;
    private Instant accessTokenIssuedAt;
    private Instant accessTokenExpiresAt;
    @Type(JsonType.class)
    @Column(columnDefinition = "json")
    private Map<String, Object> accessTokenMetadata;
    private String accessTokenType;
    @Type(JsonType.class)
    @Column(columnDefinition = "json")
    private Set<String> accessTokenScopes;

    @Column(length = 1000)
    private String refreshTokenValue;
    private Instant refreshTokenIssuedAt;
    private Instant refreshTokenExpiresAt;

    @Type(JsonType.class)
    @Column(columnDefinition = "json")
    private Map<String, Object> refreshTokenMetadata;

    @Column(length = 1000)
    private String oidcIdTokenValue;
    private Instant oidcIdTokenIssuedAt;
    private Instant oidcIdTokenExpiresAt;
    @Type(JsonType.class)
    @Column(columnDefinition = "json")
    private Map<String, Object> oidcIdTokenMetadata;
    @Type(JsonType.class)
    @Column(columnDefinition = "json")
    private Map<String, Object> oidcIdTokenClaims;

    @Column(length = 1000)
    private String userCodeValue;
    private Instant userCodeIssuedAt;
    private Instant userCodeExpiresAt;
    @Type(JsonType.class)
    @Column(columnDefinition = "json")
    private Map<String, Object> userCodeMetadata;

    @Column(length = 1000)
    private String deviceCodeValue;
    private Instant deviceCodeIssuedAt;
    private Instant deviceCodeExpiresAt;
    @Type(JsonType.class)
    @Column(columnDefinition = "json")
    private Map<String, Object> deviceCodeMetadata;

    public void setAttributes(Map<String, Object> attributes) {
        for (Map.Entry<String, Object> entry : attributes.entrySet()) {

        }
        this.attributes = attributes;
    }

}