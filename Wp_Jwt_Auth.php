<?php

/**
 * 
 * @date 08/August/2023
 * @time 11:00 PM
 * 
 * @package Wp_Jwt_Auth
 * 
 * A simple JWT Auth Package 
 * 
 *  ** We are now Using For Wopress ** 
 * 
 * 
 * But You can use it in Any
 * Php Application 
 * with a Little bit of Modifications
 * 
 * 
 * This Package require jwt_token.php Class
 * that @author arafat.dml@gmail.com
 * 
 * ** It has 2 Data Dependency **
 * 
 * It must need ---
 * 
 *  1. User Object data at least ID 
 *  Object Property of a user
 * 
 *  2. It Need $request Array
 *  That Must have 2 Array Key and Data
 * 
 *  	a. login 	=> 'jon'
 * 		b. password => 'secret'
 * 
 * @author arafat.dml@gmail.com
 * 
 */ 

class Wp_Jwt_Auth{

	/**
	 *
	 * @method jwt_auth_check
	 * This will simply verify the
	 * api jwt and return wp_error()
	 * Or it will return the payload
	 * user_id
	 * 
	 * @return wp_error or user_id 
	 *
	 */
	
	static function jwt_auth_check(){

		$wp_error_or_user_id = self::verify_api_jwt();

		return $wp_error_or_user_id;
	}

	/**
	 *
	 * @method get_jwt
	 * 
	 * @param object $user, array $request
	 * 
	 * Object $user Must have ID Property that is user id
	 * 
	 * and array Request Must have
	 * 
	 * login and password array key and data
	 * 
	 * @return $jwt
	 * 
	 */
	
	static function get_jwt( object $user, array $request ){

		$jwt = self::get_or_refresh_jwt( $user, $request );

		return $jwt;
	}

	/**
	 * 
	 * @method get_or_refresh_jwt
	 * @param $user, $request
	 * 
	 * Check if it has already JWT Token 
	 * If it found the JWT token Then
	 * Check its expiration if it expire 
	 * Create a new one
	 * If not Found Create A new One
	 * If found the jwt token and it is not
	 * expired yet just return the jwt token
	 * 
	 * @return $jwt_token
	 * 
	*/
	
	static function get_or_refresh_jwt( $user, $request ){

	    $user_meta = get_user_meta($user->ID, 'my_wp_app_key_jwt', true);

	    if( $user_meta ){
	        # Meta is Found
	        # Now we need to check if it is valid and not yet Expired
	        $user_meta = json_decode( $user_meta, true );

	        # Now retrive user jwt
	        $user_jwt = $user_meta['user_jwt'];
	        # Checking if it is not Expired yet
	        $jwt_is_valid = Jwt_Token::verify_jwt_expiration( $user_jwt );
	        $jwt_is_valid =  json_decode( $jwt_is_valid, true );

	        # Jwt is is Expired or Invalid
	        if( $jwt_is_valid['error'] == 1 ){
	            # Create new KEY and JWT
	            $jwt = self::generate_and_save_jwt($user, $request);
	            return $jwt;
	        }

	        // User jwt is valid
	        // Let's Return the jwt
	        return $user_jwt;

	    }

	    # User meta for jwt not found
	    # it may not created yet or deleted
	    # Create the KEY and JWT token now
	    $jwt = self::generate_and_save_jwt($user, $request);
	    return $jwt;

	}

	/**
	 *
	 * @method generate_and_save_jwt
	 * @param $user obj and $reuest 
	 * 
	 * This method using Jwt_token.php library class
	 * using request login and password
	 * it is creating a jwt token and saving it
	 * on user_meta table for api use purpose
	 * 
	 * @return $jwt_token
	 * 
	 */
	
	static function generate_and_save_jwt($user, $request){

	    $login      = sanitize_text_field($request['login']);
	    $password   = $request['password'];

	    $key = md5($login.$password.time());

	    $payload = array(
	        'use_for' => 'api_call',
	        'user_id' => $user->ID,
	        'iat'     => time(),
	        // expire in 3 days
	        'exp'     => time()+( 60*60*24*3 )
	    );
	    # Calling the Jwt Class
	    # Set the Payload 
	    Jwt_Token::set_payload( $payload );

	    # Set The Key
	    Jwt_Token::set_key( $key );

	    # Generate Jwt Token
	    $jwt_token = Jwt_Token::generate_jwt_token();

	    # Now Save the data to user meta
	    $user_jwt_data = array(
	        'user_key' => $key,
	        'user_jwt' => $jwt_token,
	    );

	    # Now save it on user meta
	    update_user_meta($user->ID, 'my_wp_app_key_jwt', json_encode( $user_jwt_data ) );

	    # Now Return JWT
	    return $jwt_token;

	}


	

	/**
	 *
	 * @method verify_api_jwt
	 * 
	 * This method will take HTTP_AUTHORIZATION jwt and validate 
	 * it. if validation pass it will send the user id from 
	 * jwt payload. If any error occour during the validation
	 * process then it will return that error
	 * 
	 * @return $user_id or $erros if there any ?
	 *
	 */
	
	static function verify_api_jwt(){

	    // Check if the Authorization header is present
	    if (!isset($_SERVER['HTTP_AUTHORIZATION'])) {

	        return new WP_Error('jwt_auth_validation_error',  __( 'Authorization header missing', MY_WP_APP_DOMAIN ), array('status' => 401));
	    }

	    // Get the JWT token from the Authorization header
	    $auth_header = $_SERVER['HTTP_AUTHORIZATION'];
	    $jwt = str_replace('Bearer ', '', $auth_header);

	    $jwt_arr = explode('.', $jwt);

	    # Remove empty value from array
	    $jwt_arr = array_filter( $jwt_arr );

	    # If it is not valid jwt token then
	    if( !$jwt_arr || 
	    ( is_array($jwt_arr) && count( $jwt_arr ) != 3 ) ){

	        return new WP_Error( 'invalid_jwt', __( 'Not a Valid JWT Token. Please Try Again.', MY_WP_APP_DOMAIN ), array( 'status' => 401 ) );
	    }

	    # We need the payload to get the user_id
	    $payload = json_decode( base64_decode( $jwt_arr[1] ), true );

	    # We need the user id It should contain the jwt Payload
	    # In before we set this data in payload if it is not there
	    # Someone tempered with it
	    if( !isset( $payload['user_id'] ) ){

	        return new WP_Error( 'invalid_jwt_payload', __( 'Not a Valid JWT Token. Required Payload Data Not Found. Please Try Again.', MY_WP_APP_DOMAIN ), array( 'status' => 401 ) );
	    }

	    $user_id = $payload['user_id'];

	    # Getting our user meta by user id
	    $user_meta = get_user_meta($user_id, 'my_wp_app_key_jwt', true);

	    if( !$user_meta ){
	        # Meta is not found
	        return new WP_Error( 'jwt_not_found', __( 'The JWT is not found may be it is deleted or modified. Login again to get the updated JWT', MY_WP_APP_DOMAIN ), array( 'status' => 401 ) );
	    }

	    # Decode our arr values
	    $user_meta = json_decode( $user_meta, true );
	    
	    # Getting user_key from user meta
	    $user_key = $user_meta['user_key'];
	    
	    # Set the Jwt key 
	    Jwt_Token::set_key( $user_key );

	    # Now Verify the Jwt
	    $response = Jwt_Token::verify_jwt( $jwt );

	    # Decoding json response
	    $response =  json_decode( $response, true );

	    # If we found any error return that
	    if( $response['error'] == 1 ){
	        # we have error in verifying jwt
	        return new WP_Error( 'jwt_verify_error', $response['msg'], array( 'status' => 401 ) );
	    }

	    # Every Check Passed 
	    # Now return the user id.
	    return $user_id;
	}


}


/**
 *
 * Below is an Example Of How To Send a JWT Request To the
 * Api Using JWT 
 * We are showing using php CURL
 *
 */


/*

// -----------------------------------------------------------------
// Copy the Below code for a test
// ------------------------------------------------------------------

$jwt_token = 'paste_your_jwt_token_here';
$api_url = 'http://localhost/wp_dev/wp-json/my-wp-app/v1/health';
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $api_url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, array(
'Authorization: Bearer ' . $jwt_token,
));
$response = curl_exec($ch);
if (curl_errno($ch)) {
echo 'cURL Error: ' . curl_error($ch);
}
curl_close($ch);
echo $response;

// -----------------------------------------------------------------
// End test Code
// ------------------------------------------------------------------

*/

