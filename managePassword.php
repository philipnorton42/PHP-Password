<?php

include("Password.php");
$password = new Password();
$genPass = "";
$score = $passwordInput = "No password submitted.";

if (isset($_POST["gen"])) {$genPass = $password->generatePassword();}

if (isset($_GET["password"])) {
    $passwordInput = $_GET["password"];
    $score = $password->scorePassword($passwordInput);
}

?>
 
<html>
    <head>
        <title>Manage Password</title>
        <link rel="stylesheet" type="text/css" href="style/style.css">
    </head>
    <body>
        <h1>Manage Password</h1>
            <form action="/Password/managePassword.php" method="GET">
                Enter password:
                <input type="text" name="password" value="<?php echo $genPass; ?>" />
                <br />
                <input type="submit" value="Score" />
            </form>
        <div id="genBtn">
            <form action="/Password/managePassword.php" method="POST">
                <input type="submit" name="gen" value="Generate" />
            </form>
        </div>
        <p><b>Password:</b> <?php echo $passwordInput; ?></p>
        <p><b>Score:</b> <?php echo $score; ?></p>
        </body>
</html>
