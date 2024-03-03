package study.springoauth2authserver.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import study.springoauth2authserver.entity.Authority;

public interface AuthorityRepository extends JpaRepository<Authority, Long> {
}
