package dynamind.oauth2.client;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class UserController {

    @Autowired
    private OAuth2RestOperations restTemplate;

    // API請求網址
    @Value("${config.oauth2.resourceURI}")
    private String resourceURI;

    @RequestMapping("/")
    public JsonNode home() {
    	// 回傳該網址的response格式ByJsonNode.class
        return restTemplate.getForObject(resourceURI, JsonNode.class);
    }

}