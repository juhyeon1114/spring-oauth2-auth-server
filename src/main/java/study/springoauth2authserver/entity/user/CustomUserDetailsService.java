package study.springoauth2authserver.entity.user;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;


@Slf4j
@Transactional
@Component
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        study.springoauth2authserver.entity.user.User user = getUserByUsername(username);
        return User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .disabled(!user.getEnabled())
                .accountExpired(!user.getAccountNonExpired())
                .accountLocked(!user.getAccountNonLocked())
                .credentialsExpired(!user.getCredentialsNonExpired())
                .authorities(user.getSimpleAuthorities())
                .build();
    }

    public study.springoauth2authserver.entity.user.User getUserByUsername(String username) throws UsernameNotFoundException {
        study.springoauth2authserver.entity.user.User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException(username);
        }
        return user;
    }


}
