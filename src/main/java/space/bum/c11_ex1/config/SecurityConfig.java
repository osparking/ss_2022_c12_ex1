package space.bum.c11_ex1.config;


import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class SecurityConfig {
	/* 오소리 서버에 오소리 코드 요청 URL 
		 http://localhost:8080/oauth2/authorize?response_type=code&client_id=client&scope=openid&redirect_uri=https://springone.io/authorized&code_challenge=ojZHkZKUHL6x7_AuS48va_A39Fz2Hg1z7TUgKGdOj78&code_challenge_method=S256
		 
		 
		 http://localhost:8080/oauth2/token?client_id=client&redirect_uri=https://springone.io/authorized&grant_type=authorization_code&code=dWlJMGpGlUAPz0sRU1y8suXDyWejo0_B4-WrLP-ks5kSlcdvlGG-u1OxOORvvpm7IMJaC_lMqzTX2Oh6AKHGOb2J4-Hp6PVPvGjLeUQMnWzz6h3Xyy1D0S6czbiTeU8f&code_verifier=qPsH306-ZDDaOE8DFzVn05TkN3ZZoVmI_6x4LsVglQI
	 */
	@Bean
	@Order(1)
	SecurityFilterChain asSecurityFilterChain(HttpSecurity http)
			throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
				.oidc(Customizer.withDefaults());
		
		http.exceptionHandling(e ->
				e.authenticationEntryPoint(
						new LoginUrlAuthenticationEntryPoint("/login")
						)
				);
		
		return http.build();
	}

	// @formatter:off
	@Bean
	@Order(2)
	SecurityFilterChain appSecurityFilterChain(HttpSecurity http)
			throws Exception {
		http.formLogin().and()
			.authorizeHttpRequests().anyRequest().authenticated();

		return http.build();
	}
	
	@Bean
	UserDetailsService userDetailsService() {
		var user = User.withUsername("park")
				.password("1234")
				.authorities("read").build();
		
		return new InMemoryUserDetailsManager(user);
	}
	
	@SuppressWarnings("deprecation")
	@Bean
	PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}

	// @formatter:off
	@Bean
	RegisteredClientRepository registeredClientRepository() {
		var r1 = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("client")
				.clientSecret("secret")
				.clientAuthenticationMethod(
						ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.redirectUri("https://springone.io/authorized")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.build();

		return new InMemoryRegisteredClientRepository(r1);
	}
	// @formatter:on
	
	@Bean
	AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder()
				.build();
	}
	
	@Bean
	JWKSource<SecurityContext> jwkSource() 
															throws NoSuchAlgorithmException {
		KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
		kg.initialize(2048);
		KeyPair kp = kg.generateKeyPair();
		
		RSAPublicKey pubKey = (RSAPublicKey) kp.getPublic();
		RSAPrivateKey priKey = (RSAPrivateKey) kp.getPrivate();
		
		RSAKey key = new RSAKey.Builder(pubKey)
				.privateKey(priKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		
		JWKSet set = new JWKSet(key);
		return new ImmutableJWKSet<SecurityContext>(set);
	}
	// @formatter:on
}
