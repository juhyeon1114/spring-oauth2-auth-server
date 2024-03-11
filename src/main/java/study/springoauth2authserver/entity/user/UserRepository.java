package study.springoauth2authserver.entity.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import study.springoauth2authserver.entity.user.User;

public interface UserRepository extends JpaRepository<User, Long> {

    @Query("SELECT user FROM User user JOIN FETCH user.authorities WHERE user.username=:username")
    User findByUsername(String username);

}
