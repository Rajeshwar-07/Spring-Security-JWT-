package com.security.restController;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.security.entity.Customer;
import com.security.repository.CustomerRepo;
import com.security.service.JwtService;

@RestController
@RequestMapping("api")
public class CustomerRestController {

	@Autowired
	private CustomerRepo customerRepo;
	@Autowired
	private PasswordEncoder encoder;

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JwtService jwtService;

	@GetMapping("/welcome")
	public ResponseEntity<String> welcome() {
		return new ResponseEntity<String>("Welcome.....!!!!!", HttpStatus.OK);
	}

	@PostMapping("/login")
	public ResponseEntity<String> login(@RequestBody Customer customer) {

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(customer.getEmail(),
				customer.getPassword());

		Authentication authenticate = authenticationManager.authenticate(token);

		if (authenticate.isAuthenticated()) {
			String jwt = jwtService.generateToken(customer.getEmail());
			return new ResponseEntity<String>(jwt, HttpStatus.OK);
		}

		return new ResponseEntity<String>("Invalid Credential", HttpStatus.BAD_REQUEST);
	}

	@PostMapping("/register")
	public ResponseEntity<String> register(@RequestBody Customer customer) {

		String encode = encoder.encode(customer.getPassword());
		customer.setPassword(encode);

		customerRepo.save(customer);

		return new ResponseEntity<>("Customer Registered Successfully....!!!", HttpStatus.CREATED);
	}
}
