<?php

include("Password.php");
$password = new Password();

if(!empty($_POST["minLength"])){ $password->setMinLength($_POST["minLength"]); }
if(!empty($_POST["maxLength"])){ $password->setMaxLength($_POST["maxLength"]); }
if(!empty($_POST["minSymbols"])){ $password->setMinSymbols($_POST["minSymbols"]); }
if(!empty($_POST["maxSymbols"])){ $password->setMaxSymbols($_POST["maxSymbols"]); }
if(!empty($_POST["allowedSymbols"])){ $password->setAllowedSymbols(str_split($_POST["allowedSymbols"])); }

$newPassword = $password->generatePassword();

?>

<html>
    <head><title>Password Generator</title></head>
    <body>
    <h1>Generate Password</h1>
        <form action="/Password/generatePassword.php" method="POST">
            <input type="text" name="minLength" placeholder="min length" />
            <input type="text" name="maxLength" placeholder="max length" />
            <input type="text" name="minSymbols" placeholder="min symbols" />
            <input type="text" name="maxSymbols" placeholder="max symbols" />
            <input type="text" name="allowedSymbols" placeholder="allowed symbols" />
            <input type="text" name="amount" placeholder="amount" />
            <input type="submit" value="Generate New" />
        </form>
        Password: <textarea rows="1" cols="15"><?php echo $newPassword; ?></textarea>
    </body>
</html>
