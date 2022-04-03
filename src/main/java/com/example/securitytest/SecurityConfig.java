package com.example.securitytest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.http.HttpSession;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 메모리단에 임시 사용자 만들어서 접근 권한 확인용
        auth.inMemoryAuthentication()
                .withUser("user").password("{noop}1111").roles("USER")
                .and()
                .withUser("sys").password("{noop}1111").roles("SYS", "USER")
                .and()
                .withUser("admin").password("{noop}1111").roles("ADMIN", "SYS", "USER");
    }

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorizeRequests -> authorizeRequests
                        .antMatchers("/login").permitAll()
                        .antMatchers("/user").hasRole("USER")
                        .antMatchers("/admin/pay").hasRole("ADMIN")
                        .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                        .anyRequest().authenticated()
                )
                .formLogin(formLogin -> formLogin
                        .defaultSuccessUrl("/")
                        .permitAll()
                        .successHandler((request, response, authentication) -> {
                            RequestCache requestCache = new HttpSessionRequestCache();
                            final SavedRequest savedRequest = requestCache.getRequest(request, response);

                            response.sendRedirect(savedRequest.getRedirectUrl());
                        })
                )
                .logout(logout -> logout
                        .logoutUrl("/logout") // default
                        .logoutSuccessUrl("/login") // default
                        .addLogoutHandler((request, response, authentication) -> {
                            HttpSession session = request.getSession();
                            session.invalidate();
                        })
                        .logoutSuccessHandler((request, response, authentication) -> {
                            response.sendRedirect("/login");
                        })
                        .deleteCookies("remember-me")
                )
                .rememberMe(rememberMe -> rememberMe
                        .rememberMeParameter("remember")    // default: remember-me
                        .tokenValiditySeconds(3600)         // default: 1209600(14일)
                        .alwaysRemember(true)               // default: false  리멤버 미 체크하지 않아도 항상 적용(권장X 필요시)
//                        .userDetailsService(userDetailsService)
                )
                .sessionManagement(sessionManagement -> sessionManagement
                        .sessionFixation().changeSessionId()// default
                        .maximumSessions(1)                 // default: -1
                        .maxSessionsPreventsLogin(false)    // default: false
                )
                .exceptionHandling(exceptionHandling -> exceptionHandling
//                        .authenticationEntryPoint((request, response, authException) -> {
//                            response.sendRedirect("/login");
//                        })
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.sendRedirect("/denied");
                        })
                );
    }
}
