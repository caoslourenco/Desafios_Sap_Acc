package acc.br.login.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security configuration class for setting up security rules.
 */
@Configuration
public class SecurityConfig {

    @Autowired
    private final UserDetailsService userDetailsService;

    @Autowired
    private final PasswordEncoder passwordEncoder;

    // ------------------- Construtor -------------------

    public SecurityConfig(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    // ------------------- Bean de Configuração -------------------

    /**
     * Configura as regras de segurança HTTP com autenticação e autorização.
     * @param http HttpSecurity
     * @return SecurityFilterChain
     * @throws Exception
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Configuração de CSRF (desabilitada para testes)
            .csrf(csrf -> csrf.disable())
            
            // Configuração de autorizações
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/register", "/login", "/h2-console/**").permitAll()
                .anyRequest().authenticated()
            )
            
            // Configuração de login
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
                .defaultSuccessUrl("/home", true) // Redireciona para "/home" após login bem-sucedido
                .failureUrl("/login?error=true") // Redireciona para "/login" em caso de erro
            )
            
            // Configuração de logout
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout=true")
                .permitAll()
            )
            
            // Configuração do serviço de detalhes do usuário
            .userDetailsService(userDetailsService)
            
            // Configuração de cabeçalhos (para suportar H2 Console)
            .headers(headers -> headers.frameOptions(frame -> frame.disable()));

        return http.build();
    }

    // ------------------- Fim da Configuração -------------------
}
