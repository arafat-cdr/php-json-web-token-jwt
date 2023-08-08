## JWT (Json Web Token)

> * The client application should store the JWT and send it with every request to the API. If the token is stolen, a malicious third party can impersonate the legitimate user for as long as the token is valid. Therefore, it’s crucial to take all possible measures to keep the token secure.

> * There are two standard ways to store the token: 
	* in the local/session storage of the browser, 
	* or in a cookie. 

### Here are the main risks and considerations when deciding which option to choose:

#### Man in the middle attacks – you need to make sure that the application only works over https so it’s not possible to sniff the token by intercepting the traffic (e.g. in a public wi-fi network).

### To summarize, here’s the secure way to handle JWTs:

* **Sign your tokens with a strong key, and keep their expiration times low.
Store them in https-only cookies.

* **Use the SameSite=strict cookie attribute if it doesn’t affect your application’s functionality.

* **Use your Web application framework’s default way of dealing with CSRF if SameSite=strict is not an option for you.

* **Build your own CSRF token and backend code to verify each form request if you’re unlucky enough to use a framework that doesn’t handle CSRF out of the box.

* **Always verify the signature on the server side before you trust any information in the JWT.

### What is a JWT Token ?

> #### Answer:: header.payload.signature


JSON Web Tokens (JWT) is a widely used standard for securely transmitting information between parties as a JSON object. It is commonly used in web-based authentication and authorization systems. The main idea behind JWT is to enable stateless authentication, meaning the server does not need to store any session information. Instead, all necessary data is contained within the token itself, making it easy to scale and distribute across multiple services or servers.

> A JWT is comprised of three parts, each separated by a period ('.'):

1. Header
2. Payload (also called Claims)
3. Signature

Let's dive into each part in detail:

### 1. Header:
The header typically consists of two parts: the token type (typ) and the signing algorithm used (alg). The typ identifies the type of token, which is "JWT" in this case. The alg specifies the algorithm used to sign the token.

```json
{
  "typ": "JWT",
  "alg": "HS256"
}

```

### 2. Payload (Claims):
The payload contains the claims. Claims are statements about an entity (usually the user) and additional data. There are three types of claims:

1. registered, 
2. public, and 
3. private claims.


### 1. Registered Claims:
These are predefined claims with specific meanings. Some examples include 

	* "iss" (issuer), 
	* "sub" (subject), 
	* "exp" (expiration time), and 
	* "iat" (issued at time).


### 2.Public Claims: 
These claims are not registered but are used to share information between parties that agree on using them.

### 3.Private Claims: 
These claims are custom claims created for a specific use case between parties.
Example Payload:

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "role": "admin",
  "iat": 1628216058,
  "exp": 1628219658
}

```

### 3.Signature:

The signature is created by combining the 
1. encoded header
2.  encoded payload and 
3.  secret key 

(or a public-private key pair) using the specified algorithm. **The server-side knows the secret key** and can use it to verify the authenticity of the token later.

To create the signature, you take the 

>> encoded header and encoded payload, concatenate them with a period separator, and then apply the signing algorithm.

Example Signature (using HMAC-SHA256):

```php
<?php

$signature = hash_hmac('SHA256', $headers_encoded.$payload_encoded, $key);
$signature_encoded = base64_encode($signature);

// JWT Token
$JWT_token = $headers_encoded . '.' . $payload_encoded .'.'. $signature_encoded;

```

When a client sends this token to the server, the server can decode and validate the token using the secret key. It checks if the token's signature matches the computed signature, ensuring the token hasn't been tampered with and was issued by a trusted source. The server can then use the claims within the payload for various purposes, such as authentication and authorization.

JWT is widely used due to its simplicity, self-contained nature, and ability to carry necessary information within the token itself. However, it's essential to implement JWT securely, protect the secret key, and handle token expiration and token refresh mechanisms to ensure a robust and secure authentication system.

### How to use


> #### Check How it look like a jwt token and verify jwt token and also verify expiration of the jwt token.
```php
<?php

# Checking the jwt code

// This will return an example default
echo $token =  Jwt_Token::generate_jwt_token();

// verify the token
echo Jwt_Token::verify_jwt($token);

// only verify the token expiration if it is expired
echo Jwt_Token::verify_jwt_expiration($token);

```

> ### Now Let's see a Real life example of the JWT token

```php
<?php

// This will Show a real example of JWT
// Setting Payload
$payload = array(
    'sub'     => 'Api Key',
    'user_id' => 21,
    'iat'     => time(),
    // Expire in 2 Min
    'exp'     => time()+ (60*2),
);


Jwt_Token::set_payload( $payload );

// Setting Key
Jwt_Token::set_key('MY_RANDOM_KEY');

// Generating Token
$token = Jwt_Token::generate_jwt_token();

echo $token;

// Validating Token
echo (Jwt_Token::verify_jwt('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJBcGkgS2V5IiwidXNlcl9pZCI6MjEsImV4cCI6MTY5MTMxODI3M30=.ODczMGNlMjA3YjZlZWIyZjk3ODE4MmJkYmU0N2I2ZjBjOGRhZGFlYzM2NDFkOTlkZGYyNWRlNjU3OTMxY2M0NQ=='));

// checking if the token is expired or not yet expired
echo Jwt_Token::verify_jwt_expiration('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJBcGkgS2V5IiwidXNlcl9pZCI6MjEsImV4cCI6MTY5MTMxODI3M30=.ODczMGNlMjA3YjZlZWIyZjk3ODE4MmJkYmU0N2I2ZjBjOGRhZGFlYzM2NDFkOTlkZGYyNWRlNjU3OTMxY2M0NQ==');

```

### So How to Use this JWT_Token To A Api Auth ?

Let's talk about it .

I write a very simple class called **Wp_Jwt_Auth** This has some **static** methods That can use to verify auth

Let's see how to do that.

> #### Let's Assume we have a wp rest route that is reciving POST login and password data, for authentication and we want to validate the login and password by our own way. Then if it is valid we want to generate a jwt for that user .Then we want to send that jwt with the json reponse .

##### Here is the Example.


>#### First We are sending Post Request with data

```php
<?php
// URL to which you want to send the POST request
$url = 'http://localhost/wp_dev/wp-json/my-wp-app/v1/login-user';

// Data to be sent in the POST request
$data = array(
    'login' => 'arafat',
    'password' => 'arafat'
);

// Initialize cURL session
$ch = curl_init();

// Set cURL options
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// Execute the cURL session and get the response
$response = curl_exec($ch);

// Check for cURL errors
if (curl_errno($ch)) {
    echo 'cURL Error: ' . curl_error($ch);
}

// Close cURL session
curl_close($ch);

// Process the response
if ($response) {
    echo $response;
} else {
    echo 'Error occurred during the request.';
}

```


> ### Then We are Processing that Api POST Request This way: 

```php

<?php

require_once('Jwt_Token.php');

$user = wp_signon(
    [
        'user_login' => sanitize_text_field($request['login']),
        'user_password' => $request['password'],
        'remember' => true,
    ],
    false
);

if (is_wp_error($user)) {

    return wp_send_json_error(
        array(
            "login" => __('Failed', MY_WP_APP_DOMAIN),
            "errors" => __('Username or password is incorrect', MY_WP_APP_DOMAIN),
        ),
        401
    );
}

if (isset($user->ID)) {
    wp_set_current_user($user->ID);
    wp_set_auth_cookie($user->ID, true, false);
}

unset($user->user_pass);


// $jwt_key_generation 
// ---------------------------------------
// JWT part goes here use a new method
// Generate JWT here
// save key per user basis
// save jwt_token per user basis
// if jwt is not expred then do not create new one
// if jwt expired create new one
// if jwt is deleted from user_option Then create a new jwt in 
// user option
// ---------------------------------------

# We need to pass the login and password as array there
$req_arr = array(
    'login' => sanitize_text_field($request['login']),
    'password' => $request['password'],
);

$jwt_token = Wp_Jwt_Auth::get_jwt($user, $req_arr);

$user->jwt_token = $jwt_token;

wp_send_json_success($user);



```


> ### Now If we want to validate the JWT Token then Suppose we Have a Request This way

```php
<?php

# JWT Token
$bearer_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VfZm9yIjoiYXBpX2NhbGwiLCJ1c2VyX2lkIjoxLCJpYXQiOjE2OTE1MDc0OTAsImV4cCI6MTY5MTc2NjY5MH0=.OTkzZWM4MThjZDJhYzY4MjE0MDA1MjZlOWJlNGEyYzM1OWE3MzJjNWU3NjNlYTk0YWE1ZWQ5YjY3MzdiMWNhMg==';

// API endpoint URL
$api_url = 'http://localhost/wp_dev/wp-json/my-wp-app/v1/check';

// Initialize cURL session
$ch = curl_init();

// Set cURL options
curl_setopt($ch, CURLOPT_URL, $api_url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// Set the Authorization header with the Bearer token
curl_setopt($ch, CURLOPT_HTTPHEADER, array(
    'Authorization: Bearer ' . $bearer_token,
));

// Execute the cURL session
$response = curl_exec($ch);

// Check for cURL errors
if (curl_errno($ch)) {
    echo 'cURL Error: ' . curl_error($ch);
}

// Close the cURL session
curl_close($ch);

// Process the API response
echo $response;

```

> ### Now We can Validate the Request This way

```php

<?php

#--------------------------------------------------------------
# Checking Jwt Auth
#--------------------------------------------------------------

if (is_wp_error(Wp_Jwt_Auth::jwt_auth_check())) {

    return wp_send_json_error(Wp_Jwt_Auth::jwt_auth_check());
}

$user_id = Wp_Jwt_Auth::jwt_auth_check();

#--------------------------------------------------------------
# End Jwt Auth Checking
#-------------------------------------------------------------- 



```

> ### If we do not need the payload user_id Then We can Do This way

```php

<?php

#--------------------------------------------------------------
# Checking Jwt Auth
#--------------------------------------------------------------

if (is_wp_error(Wp_Jwt_Auth::jwt_auth_check())) {

    return wp_send_json_error(Wp_Jwt_Auth::jwt_auth_check());
}

#--------------------------------------------------------------
# End Jwt Auth Checking
#-------------------------------------------------------------- 

```

>>> #### Happy coding .