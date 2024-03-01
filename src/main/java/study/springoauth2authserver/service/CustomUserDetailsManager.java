package study.springoauth2authserver.service;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import study.springoauth2authserver.entity.User;
import study.springoauth2authserver.repository.UserRepository;

@Slf4j
@Transactional
//@Component
@RequiredArgsConstructor
public class CustomUserDetailsManager implements UserDetailsManager {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("유저를 찾을 수 없습니다");
        }
        return user;
    }

    public void createUser(String username, String password) {
        User entity = User.create(username, passwordEncoder.encode(password));
        userRepository.save(entity);
    }

    @Override
    public void createUser(UserDetails user) {
        this.createUser(user.getUsername(), user.getPassword());
    }

    @Override
    public void updateUser(UserDetails user) {
        new InMemoryUserDetailsManager();
    }

    @Override
    public void deleteUser(String username) {
        User user = userRepository.findByUsername(username);
        userRepository.delete(user);
    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {
        Authentication currentUser = this.securityContextHolderStrategy.getContext().getAuthentication();
        if (currentUser == null) {
            throw new AccessDeniedException("Can't change password as no Authentication object found in context for current user.");
        } else {
            String username = currentUser.getName();
            User entity = userRepository.findByUsername(username);
            entity.updatePassword(passwordEncoder.encode(oldPassword), passwordEncoder.encode(newPassword));
        }
    }

    @Override
    public boolean userExists(String username) {
        User user = userRepository.findByUsername(username);
        return user != null;
    }
}
