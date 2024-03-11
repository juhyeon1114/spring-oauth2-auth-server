package study.springoauth2authserver.repository;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import study.springoauth2authserver.entity.authority.Authority;
import study.springoauth2authserver.entity.authority.AuthorityRepository;
import study.springoauth2authserver.entity.user.User;
import study.springoauth2authserver.entity.user.UserRepository;

@Slf4j
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class UserRepositoryTest {

    @Autowired
    UserRepository userRepository;
    @Autowired
    AuthorityRepository authorityRepository;

    @Autowired
    BCryptPasswordEncoder passwordEncoder;


    @Test
    @DisplayName("createUser")
    public void createUser() throws Exception {
        User entity = User.create("hello", passwordEncoder.encode("1234"));
        User user = userRepository.save(entity);

        Authority authority = Authority.builder().authority("USER").user(user).build();
        authorityRepository.save(authority);
    }

}