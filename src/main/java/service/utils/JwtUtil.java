package service.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Base64;

@Component
@Slf4j
public class JwtUtil {

    @Value("${jwt.token.secret}")
    private String secretKey;

    /**
     * Token的解密
     *
     * @param token 加密后的token
     * @return
     */
    public Claims parseJWT(String token) {
        String key = Base64.getEncoder().encodeToString(secretKey.getBytes());
        Jws<Claims> claimsJws = Jwts.parser().setSigningKey(key)
                .parseClaimsJws(token);
        return claimsJws.getBody();
    }

    public String getUser(String encodedToken) {
        try {
            Claims token = parseJWT(encodedToken);
            if (token.containsKey("user_no")) {
                return token.get("user_no").toString();
            }
            return null;
        } catch (Exception e) {
            log.error("jwt get token error",e);
        }
        return null;
    }
}
