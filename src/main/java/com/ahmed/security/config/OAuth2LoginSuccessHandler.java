package com.ahmed.security.config;

import com.ahmed.security.model.User;
import com.ahmed.security.service.UserService;
import com.ahmed.security.util.JwtUtils;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final UserService userService;
    private final JwtUtils jwtUtils;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oauthUser = oauthToken.getPrincipal();
        String registrationId = oauthToken.getAuthorizedClientRegistrationId();
        User user = userService.authenticateOAuth2User(oauthUser, registrationId);
        String token = jwtUtils.generateTokenFromOAuth2User(user);

        Cookie jwtCookie = new Cookie("JWT_TOKEN", token);
        jwtCookie.setHttpOnly(true);
        jwtCookie.setSecure(true);
        jwtCookie.setPath("/");
        jwtCookie.setMaxAge(60 * 60);
        response.addCookie(jwtCookie);

        getRedirectStrategy().sendRedirect(request, response, "http://localhost:5500/");
    }
}

