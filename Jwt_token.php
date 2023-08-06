<?php

/**
 * 
 * @package Jwt_token
 * A simple JWT Token Generation and
 * validator 
 * @author: arafat.dml@gmail.com
 * 
 */ 
class Jwt_Token {

private static $payload = array(
    'sub'   => 'My jwt subject',
    'name'  => 'jon doe',
    'user_id'=> 101,
    'iat'    => 12314,
    'exp'    => 4143214,
);

private static $key = 'my_secret_key_code';

static function set_payload(array $payload) {
    if (!isset($payload['exp'])) {
        // Expire in 5 Minutes
        $payload['exp'] = time() + (60 * 5);
    }
    self::$payload = $payload;
}

static function set_key($key) {
    self::$key = $key;
}

static function generate_jwt_token(array $payload = array()) {
    if (empty($payload)) {
        $payload = self::$payload;
    }

    $headers = array(
        'typ' => 'JWT',
        'alg' => 'HS256',
    );

    $headers_encoded = base64_encode(json_encode($headers));
    $payload_encoded = base64_encode(json_encode($payload));
    $signature = hash_hmac('sha256', $headers_encoded . '.' . $payload_encoded, self::$key);
    $signature_encoded = base64_encode($signature);

    $jwt_token = $headers_encoded . '.' . $payload_encoded . '.' . $signature_encoded;

    return $jwt_token;
}

static function verify_jwt($jwt_token) {

    $jwt_token_arr = explode('.', $jwt_token);

    # Remove empty value from array
    $jwt_token_arr = array_filter( $jwt_token_arr );

    # If it is not valid jwt token then
    if( !$jwt_token_arr || 
    ( is_array($jwt_token_arr) && count( $jwt_token_arr ) != 3 ) ){

        return json_encode(
            array(
                'error' => 1,
                'msg'   => 'Not a Valid JWT Token',
                'success' => 0,
                'data'    => '',
            )
        );
    }

    $signature = base64_encode(hash_hmac('sha256', $jwt_token_arr[0] . '.' . $jwt_token_arr[1], self::$key));

    if ($signature !== $jwt_token_arr[2]) {
        return json_encode(
            array(
                'error' => 1,
                'msg'   => 'JWT Signature does not match',
                'success' => 0,
                'data'    => '',
            )
        );
    }

    $headers = json_decode(base64_decode($jwt_token_arr[0]), true);
    $payload = json_decode( base64_decode($jwt_token_arr[1]), true );

    if (isset($payload['exp']) && $payload['exp'] < time()) {
        return json_encode(
            array(
                'error' => 1,
                'msg'   => 'JWT Expired. Generate A new One',
                'success' => 0,
                'data'    => '',
            )
        );
    }

    return json_encode(
        array(
            'error' => 0,
            'msg'   => '',
            'success' => 1,
            'data'    => $payload,
        )
    );
}

}

# Checking the jwt code

// This will return an example default
// echo $token =  Jwt_Token::generate_jwt_token();

// echo Jwt_Token::verify_jwt($token);

// -----------------------------------------------

// This will Show a real example of JWT

// Setting Payload
$payload = array(
    'sub'     => 'Api Key',
    'user_id' => 21,
    // Expire in 2 Min
    'exp'     => time()+ (60*2),
);

Jwt_Token::set_payload( $payload );

// Setting Key
Jwt_Token::set_key('MY_RANDOM_KEY');

// Generating Token
$token = Jwt_Token::generate_jwt_token();

// echo $token;


// Validating Token

echo (Jwt_Token::verify_jwt('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJBcGkgS2V5IiwidXNlcl9pZCI6MjEsImV4cCI6MTY5MTMxODI3M30=.ODczMGNlMjA3YjZlZWIyZjk3ODE4MmJkYmU0N2I2ZjBjOGRhZGFlYzM2NDFkOTlkZGYyNWRlNjU3OTMxY2M0NQ=='));

