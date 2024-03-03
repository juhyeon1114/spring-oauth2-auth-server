package study.springoauth2authserver.repository;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import study.springoauth2authserver.entity.Client;
import study.springoauth2authserver.util.ClientUtils;

@Component
@RequiredArgsConstructor
public class CustomRegisteredClientRepository implements RegisteredClientRepository {

    private final ClientRepository clientRepository;
    private final ClientUtils clientUtils;

    @Override
    public void save(RegisteredClient registeredClient) {
        Client entity = clientUtils.toEntity(registeredClient);
        clientRepository.save(entity);
    }

    @Override
    public RegisteredClient findById(String id) {
        Client client = clientRepository.findById(id).orElseThrow();
        return clientUtils.toObject(client);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Client client = clientRepository.findByClientId(clientId).orElseThrow();
        return clientUtils.toObject(client);
    }
}
