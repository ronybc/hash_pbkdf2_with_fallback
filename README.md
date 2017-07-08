# hash_pbkdf2_with_fallback()
PBKDF2 PHP code; Plan B when PHP version &lt; 5.5, having no builtin hash_pbkdf2(). 
(On a web host running older PHP version.)

# Test:
```
include 'pbkdf2.php';

$password = "fish ash shaving_lotion";
$salt = base64_encode( openssl_random_pseudo_bytes(32) );

echo hash_pbkdf2_with_fallback('sha256', $password, $salt, 10000, 32, false);
echo bin2hex( hash_pbkdf2_with_fallback('sha256', $password, $salt, 10000, 16, true) );
```
