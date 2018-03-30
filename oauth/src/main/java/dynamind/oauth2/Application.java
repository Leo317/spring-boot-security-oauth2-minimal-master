package dynamind.oauth2;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.web.SpringBootServletInitializer;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@SpringBootApplication
public class Application extends SpringBootServletInitializer {

    private static final Logger log = LoggerFactory.getLogger(Application.class);

    public static void main(String[] args) {
        ApplicationContext context = SpringApplication.run(Application.class, args);
    }

    /**
     * An opinionated WebApplicationInitializer to run a SpringApplication from a traditional WAR deployment.
     * Binds Servlet, Filter and ServletContextInitializer beans from the application context to the servlet container.
     *
     * @link http://docs.spring.io/spring-boot/docs/current/api/index.html?org/springframework/boot/context/web/SpringBootServletInitializer.html
     */
    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(Application.class);
    }

    @Configuration
    @EnableWebSecurity
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    protected static class SecurityConfig extends WebSecurityConfigurerAdapter {
    	// (B) 使用者認證的帳號密碼
        @Override
        @Autowired // <-- This is crucial otherwise Spring Boot creates its own
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        	System.out.println("OAuth ~~~~~~~~~~~~  WebSecurityConfig~~~~~~~~~~~~~~~~~~~   56~~~~~~~~~~");
        	// WebSecurityConfigurerAdapter 底下新增兩個使用者
        	// 先配置一個正常的驗證，可在extend出別的並以order(n)，來指定執行順序，n為整數
            log.info("Defining inMemoryAuthentication (2 users)");
            auth
                    .inMemoryAuthentication()

                    .withUser("user").password("password")
                    .roles("USER")

                    .and()

                    .withUser("admin").password("password")
                    .roles("USER", "ADMIN")
            ;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
        	System.out.println("OAuth ~~~~~~~~~~~~  HttpSecurity~~~~~~~~~~~~~~~~~~~   75~~~~~~~~~~");
        	// antMatcher("/api/**")指出，这个HttpSecurity只应用到以/api/开头的URL上。
        	// 此處沒有antMatcher()故所有的URL都需要驗證
        	// hasRole("ADMIN") 權限管控也是這邊設定
            http
                    .formLogin()

                    .and()

                    .httpBasic().disable()
                    .anonymous().disable()
                    .authorizeRequests().anyRequest().authenticated()
            ;
            // 認證需求，所有的需求，驗證
        }
    }

    @Configuration
    @EnableAuthorizationServer
    protected static class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

        @Value("${config.oauth2.privateKey}")
        private String privateKey;

        @Value("${config.oauth2.publicKey}")
        private String publicKey;

        @Autowired
        private AuthenticationManager authenticationManager;

        @Bean
        public JwtAccessTokenConverter tokenEnhancer() {
        	System.out.println("OAuth ~~~~~~~~~~~~  JwtAccessToken~~~~~~~~~~~~~~~~~~~   107~~~~~~~~~~");
            log.info("Initializing JWT with public key:\n" + publicKey);
            JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
            converter.setSigningKey(privateKey);
            converter.setVerifierKey(publicKey);
            return converter;
        }

        @Bean
        public JwtTokenStore tokenStore() {
        	System.out.println("OAuth ~~~~~~~~~~~~  JwtTokenStore~~~~~~~~~~~~~~~~~~~   117~~~~~~~~~~");
            return new JwtTokenStore(tokenEnhancer());
        }

        /**
         * Defines the security constraints on the token endpoints /oauth/token_key and /oauth/check_token
         * Client credentials are required to access the endpoints
         *
         * @param oauthServer
         * @throws Exception
         */
        @Override
        public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        	System.out.println("OAuth ~~~~~~~~~~~~  AuthorizationServerSecurity~~~~~~~~~~~~~~~~~~~   130~~~~~~~~~~");
            oauthServer
                    .tokenKeyAccess("isAnonymous() || hasRole('ROLE_TRUSTED_CLIENT')") // permitAll() //允許訪問TokenKeyEndpoint
                    .checkTokenAccess("hasRole('TRUSTED_CLIENT')"); // isAuthenticated() //允許訪問CheckTokenEndpoint
        }

        /**
         * Defines the authorization and token endpoints and the token services
         *
         * @param endpoints
         * @throws Exception
         */
        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        	log.error("ERROR {}", "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR");
        	System.out.println("RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR");
            endpoints

                    // Which authenticationManager should be used for the password grant
                    // If not provided, ResourceOwnerPasswordTokenGranter is not configured
                    .authenticationManager(authenticationManager)

                            // Use JwtTokenStore and our jwtAccessTokenConverter
                    .tokenStore(tokenStore())
                    .accessTokenConverter(tokenEnhancer())
            ;
            System.out.println("RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR");
        }

        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        	System.out.println("OAuth ~~~~~~~~~~~~  ClientDetailsServer~~~~~~~~~~~~~~~~~~~   161~~~~~~~~~~");
            clients.inMemory()
            		// 確認客戶識別碼 && URI && SCOPE
                    // Confidential client where client secret can be kept safe (e.g. server side)
                    .withClient("confidential").secret("secret")
                    .authorizedGrantTypes("client_credentials", "authorization_code", "refresh_token")
                    .scopes("read", "write")
                    .redirectUris("http://localhost:8080/client/")
                    .accessTokenValiditySeconds(120)
                    .refreshTokenValiditySeconds(5000)

                    .and()

                            // Public client where client secret is vulnerable (e.g. mobile apps, browsers)
                    .withClient("public") // No secret!
                    .authorizedGrantTypes("implicit")
                    .scopes("read")
                    .redirectUris("http://localhost:8080/client/")
                    .accessTokenValiditySeconds(120)
                    .refreshTokenValiditySeconds(5000)

                    .and()

                            // Trusted client: similar to confidential client but also allowed to handle user password
                    .withClient("trusted").secret("secret")
                    .authorities("ROLE_TRUSTED_CLIENT")
                    .authorizedGrantTypes("client_credentials", "password", "authorization_code", "refresh_token")
                    .scopes("read", "write")
                    .redirectUris("http://localhost:8080/client/")
                    .accessTokenValiditySeconds(120)
                    .refreshTokenValiditySeconds(5000)
            ;
        }

    }

}
