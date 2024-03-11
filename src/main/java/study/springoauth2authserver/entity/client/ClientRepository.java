package study.springoauth2authserver.entity.client;

import org.springframework.data.jpa.repository.JpaRepository;
import study.springoauth2authserver.entity.client.Client;

import java.util.Optional;

public interface ClientRepository extends JpaRepository<Client, String> {

    Optional<Client> findByClientId(String clientId);

}
