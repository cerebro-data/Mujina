package mujina.idp;

import mujina.api.IdpConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static mujina.api.AuthenticationMethod.ALL;

public class AuthenticationProvider implements org.springframework.security.authentication.AuthenticationProvider {

  private final IdpConfiguration idpConfiguration;
  protected final Logger LOG = LoggerFactory.getLogger(getClass());

  public AuthenticationProvider(IdpConfiguration idpConfiguration) {
    this.idpConfiguration = idpConfiguration;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    if (idpConfiguration.getAuthenticationMethod().equals(ALL)) {
      return new UsernamePasswordAuthenticationToken(authentication.getPrincipal(), authentication.getCredentials(), Arrays.asList(
        new SimpleGrantedAuthority("ROLE_ADMIN"), new SimpleGrantedAuthority("ROLE_USER")
      ));
    } else {

      boolean userExists;
      List<UsernamePasswordAuthenticationToken> foundUsers =
          idpConfiguration.getUsers().stream().filter(token ->
              token.getPrincipal().equals(authentication.getPrincipal())).
              collect(Collectors.toList());

      // Add a valid user if they don't already exist
      if (foundUsers.size() == 0) {
        LOG.debug("Principle : " + authentication.getPrincipal() + " not found, adding it");
        // Require that the principal match the credential (password) for new users to be considered valid.
        if (!authentication.getPrincipal().equals(authentication.getCredentials())) {
          String errorString = "Principal: " + authentication.getPrincipal() + " != " +
              authentication.getCredentials();
          LOG.error(errorString);
          throw new AuthenticationException("User not found or bad credentials") {};
        }
        idpConfiguration.getUsers().add(
          new UsernamePasswordAuthenticationToken(
            authentication.getPrincipal(),
            authentication.getCredentials(),
            Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"),
                          new SimpleGrantedAuthority("ROLE_ADMIN"))));
        LOG.info("Added user: " + authentication.getPrincipal());
      }


      return idpConfiguration.getUsers().stream()
        .filter(token ->
          token.getPrincipal().equals(authentication.getPrincipal()) &&
          token.getCredentials().equals(authentication.getCredentials()))
        .findFirst().map(usernamePasswordAuthenticationToken -> new UsernamePasswordAuthenticationToken(
          //need top copy or else credentials are erased for future logins
          usernamePasswordAuthenticationToken.getPrincipal(),
          usernamePasswordAuthenticationToken.getCredentials(),
          usernamePasswordAuthenticationToken.getAuthorities()
        ))
        .orElseThrow(() -> new AuthenticationException("User not found or bad credentials") {
        });
    }
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
  }
}
