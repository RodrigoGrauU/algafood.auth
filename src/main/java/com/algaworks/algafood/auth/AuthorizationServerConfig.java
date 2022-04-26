package com.algaworks.algafood.auth;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
	private JwtKeyStoreProperties jwtKeyStoreProperties;
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients
			.inMemory()
				.withClient("algafood-web")
				.secret(passwordEncoder.encode("web123"))
				.authorizedGrantTypes("password", "refresh_token", "client")
				.scopes("write", "read")
//				.accessTokenValiditySeconds(60 * 60 * 6) // 6 horas (padrão é 12 horas);
				.refreshTokenValiditySeconds(60 * 24 * 60 * 60) //60 dias
				
			.and()
				.withClient("foodanalytics")
//				.secret(passwordEncoder.encode("food123"))
				.secret(passwordEncoder.encode(""))
				.authorizedGrantTypes("authorization_code")
				.scopes("write", "read")
				.redirectUris("http://localhost:8000")
			
			.and()
				.withClient("webadmin")
				.authorizedGrantTypes("implicit")
				.scopes("write", "read")
				.redirectUris("http://aplicacao-cliente")
				
			.and()
				.withClient("faturamento")
				.secret(passwordEncoder.encode("faturamento123"))
				.authorizedGrantTypes("client_credentials")
				.scopes("write", "read")
			
			.and()
				//usado um id e senha para o resource server (só para diferenciar do client)
				.withClient("checktoken")
				.secret(passwordEncoder.encode("check123"));
//		.and()
//			.withClient("app-mobile")
//			.secret(passwordEncoder.encode("web123"))
//			.authorizedGrantTypes("password")
//			.scopes("write", "read");
			
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
//		security.checkTokenAccess("isAuthenticated()");
		security.checkTokenAccess("permitAll()") //nao precisa autenticacao do client
			.tokenKeyAccess("permitAll()")
			.allowFormAuthenticationForClients(); //permite enviar o client_id pelo form (util para o PKCE)
	}
	
	//para o password flow
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints
			.authenticationManager(authenticationManager)
			.userDetailsService(userDetailsService)
			.reuseRefreshTokens(false)
			.accessTokenConverter(jwtAccessTokenConverter())
			.approvalStore(approvalStore(endpoints.getTokenStore()))
			.tokenGranter(tokenGranter(endpoints));
	}
	
	private ApprovalStore approvalStore(TokenStore tokenStore) {
		var approvalStore = new TokenApprovalStore();
		approvalStore.setTokenStore(tokenStore);
		return approvalStore;
	}
	
	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
//		jwtAccessTokenConverter.setSigningKey("dsa9d7asd9as8dfa7s0df9sa78dasdc7cxvxsdv2sdabvdg324xcv");
		
		var jksResource = new ClassPathResource(jwtKeyStoreProperties.getPath());
		var keyStorePass = jwtKeyStoreProperties.getPassword();
		var keyPairAlias = jwtKeyStoreProperties.getKeypairAlias();
		
		var keyStoreKeyFactory = new KeyStoreKeyFactory(jksResource, keyStorePass.toCharArray());
		var keyPair = keyStoreKeyFactory.getKeyPair(keyPairAlias);
		
		jwtAccessTokenConverter.setKeyPair(keyPair);
		
		return jwtAccessTokenConverter;
	}
	
	private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
		var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
				endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
				endpoints.getOAuth2RequestFactory());
		
		var granters = Arrays.asList(
				pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());
		
		return new CompositeTokenGranter(granters);
	}
}
