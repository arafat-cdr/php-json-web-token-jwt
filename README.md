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

>>> #### Happy coding .