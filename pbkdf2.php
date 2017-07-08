<?php

/*
 * PBKDF2 - PHP implementation
 *
 * git: https://github.com/ronybc/hash_pbkdf2_with_fallback
 * 
 * Based on:
 * http://www.php.net/manual/en/function.hash-hmac.php#101540
 * https://gist.github.com/inanimatt/1162409
 * 
 * Written by: Rony B Chandran (http://www.ronybc.com)
 * 
 * 
 * Example:
 * 
 * include 'pbkdf2.php';
 * 
 * $password = "fish ash shaving_lotion"; // genuine 
 * $salt = base64_encode( openssl_random_pseudo_bytes(32) );
 * 
 * echo hash_pbkdf2_with_fallback('sha256', $password, $salt, 10000, 64, false);
 * echo bin2hex( hash_pbkdf2_with_fallback('sha256', $password, $salt, 10000, 32, true) );
 * 
**/

function hash_pbkdf2_with_fallback($algorithm, $password, $salt, $rounds, $key_length, $raw_output)
{
	if(function_exists('hash_pbkdf2'))
	{
		// Have builtin hash_pbkdf2() (PHP >= 5.5.0)
		return hash_pbkdf2($algorithm, $password, $salt, $rounds, $key_length, $raw_output);
	}

	// $raw_output = false ; output 'key_length' number of characters (hex)
	// $raw_output = true  ; output 'key_length' number of bytes

	if($raw_output == false)
	{
		$bytes = $key_length / 2;
	}
	else
	{
		$bytes = $key_length;
	}
	
	$dk = '';
	$block = 1;
	
	do
	{ 
		$ib = $h = hash_hmac($algorithm, $salt . pack('N', $block), $password, true);

		for ($i=1; $i<$rounds; $i++)
		{
			$ib ^= ($h = hash_hmac($algorithm, $h, $password, true));
		}

		$dk .= $ib;
		$block++;
		
	}	while(strlen($dk) < $bytes);

	if($raw_output == 0)
	{
		$dk = bin2hex($dk);
	}
	
	// if 0 is passed, the entire output of the supplied algorithm is used.
	
	if($key_length != 0)
	{
		$dk = substr($dk, 0, $key_length);
	}
	
	return($dk);
}

?>
