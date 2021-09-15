package com.springsecurityjwt.controller;
import com.springsecurityjwt.model.AuthenticationRequest;
import com.springsecurityjwt.model.AuthenticationResponse;
import com.springsecurityjwt.service.MyUserDetailsService;
import com.springsecurityjwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Controller {


    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private MyUserDetailsService userDetailsService;

    @Autowired
    private JwtUtil jwtTokenUtil;

    @GetMapping("/hello")
    public String hello() {
        return "Hello World";
    }

    /*
    Accepts user id and password
    returns JWT as response
    POST - usersending username and password in post body
    Can not call /authenticate without using username and password - permit all /authenticate requests using configure(HttpSecurity http)
    in SecurityCOnfigurer class
     */

    @PostMapping("/authenticate")
    public ResponseEntity<?> createAuthenticationRequest(@RequestBody AuthenticationRequest request) throws Exception {
        //1st authenticate
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException("Incorrect username or pssword", e);
        }
        //2nd create jwt
        //need userdetails, get userdetails using userdetailsservice
        final UserDetails userDetails = userDetailsService.loadUserByUsername(request.getUsername());
        final String jwt = jwtTokenUtil.generateToken(userDetails);
        return ResponseEntity.ok(new AuthenticationResponse(jwt));
    }

    /* Second step (To authenticate /hello API with JWT token)
    Send token in Bearer
    Intercept all incoming requests
    - extreact JWT from the header (Bearer)
    - validate and set in execution context
     */

}