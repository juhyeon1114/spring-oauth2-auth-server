package study.springoauth2authserver.entity.client;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Instant;


@Getter
@Entity
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Client {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;
    @Column(unique = true)
    private String clientId;
    private Instant clientIdIssuedAt;
    private String clientSecret;
    private Instant clientSecretExpiresAt;
    private String clientName;
    @Column(length = 1000)
    private String clientAuthenticationMethods;
    @Column(length = 1000)
    private String authorizationGrantTypes;
    @Column(length = 1000)
    private String redirectUris;
    @Column(length = 1000)
    private String postLogoutRedirectUris;
    @Column(length = 1000)
    private String scopes;
    @Column(length = 2000)
    private ClientSettings clientSettings;
    @Column(length = 2000)
    private TokenSettings tokenSettings;

}