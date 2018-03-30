package dynamind.oauth2.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.web.SpringBootServletInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;

import java.util.Arrays;

@SpringBootApplication
@EnableOAuth2Client
public class Application extends SpringBootServletInitializer {

    private static final Logger log = LoggerFactory.getLogger(Application.class);

    @Value("${config.oauth2.accessTokenUri}")
    private String accessTokenUri;

    @Value("${config.oauth2.userAuthorizationUri}")
    private String userAuthorizationUri;

    @Value("${config.oauth2.clientID}")
    private String clientID;

    @Value("${config.oauth2.clientSecret}")
    private String clientSecret;

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
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

    /**
     * The heart of our interaction with the resource; handles redirection for authentication, access tokens, etc.
     * @param oauth2ClientContext
     * @return
     */
    @Bean
    public OAuth2RestOperations restTemplate(OAuth2ClientContext oauth2ClientContext) {
    	// �O��bean�oController�{��
    	// ���O���n�����µ�resource
    	// The client uses a RestTemplate to access a protected resource (running on http://localhost:8082/api/) and discovers it is not authorized.
    	// �͑���ʹ��RestTemplate�L���ܱ��o���YԴ����http��// localhost��8082 / api /���\�У����K�l�F��δ���ڙࡣ
        return new OAuth2RestTemplate(resource(), oauth2ClientContext);
    }

    private OAuth2ProtectedResourceDetails resource() {
        AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();
        // (A) �O���͑����R�e�a && Redirection URI
        // ��Ƭ�_ϴ��˾�O��Owner���o��ClientId
        resource.setClientId(clientID);
        // ��Ƭ�_ϴ��˾�O��Owner���o��ClientSecret
        resource.setClientSecret(clientSecret);
        
        // ��Ƭ�_ϴ��˾�O��accessTokenUri = http://localhost:8081/oauth/token
        resource.setAccessTokenUri(accessTokenUri);
        // ��Ƭ�_ϴ��˾�O��userAuthorizationUri = http://localhost:8081/oauth/authorize
        resource.setUserAuthorizationUri(userAuthorizationUri);
        
        // ��Ƭ�_ϴ��˾�O����Ҫ��ȡ�ķ���
        resource.setScope(Arrays.asList("read"));

        return resource;
    }

}