Password validation and generation class in PHP.

The Password class takes a set of parameters, which can be altered at runtime, and uses these to validate a password. To run the password validator with default parameters do the following:

$password = new Password();
$password->validatePassword('password');

This will return false because it does not meet the minimum requirements needed for the password to be valid. The default password must have a minimum ength of 7 and a maximum length of 15, with at least 5 letters (at least 1 being uppercase and 1 being lowercase), containing at least 1 number and between 1 and 3 symbols. The symbols allowed are also restricted as a default to #, _ and ! but these can be changed. If the password meets the requirements of the validation then the validatePassword() function will return true. Just as an example the following password will validate to true.

$password = new Password();
$password->validatePassword('qweQWE123');

The variables can be changed at runtime using various set methods. For example, to set the maximum length of a password you would use the setMaxLength() function and pass it an integer.

$password = new Password();
$password->setMaxLength(3);
$password->validatePassword('password');

To set every different parameter at once you can pass the constructor of the password object an associative array of parameters. The allowed symbols parameter must be an array or it will not be saved.

$password = new Password(array(
  'minLength'      => 15,
  'maxLength'      => 30,
  'minNumbers'     => 5,
  'minLetters'     => 5,
  'minLowerCase'   => 5,
  'minUpperCase'   => 5,
  'minSymbols'     => 5,
  'maxSymbols'     => 10,
  'allowedSymbols' => array('#', '_', '-', '!', '[', ']', '=', '~', '*'),
));

The function setOptions() works in the same way as this, allowing you to set multiple options at runtime. It should be noted that the object will check the values of these inputs and rework them slightly if any are found that would make password validation impossible. For example, if you set a minimum password length to be greater than the maximum length then the object will set the minimum to be the same as the maximum so that a password can be validated.

There are two other functions that the Password class performs, these are scoring a password and the automatic creation of random valid passwords.

Scoring the password works by looking at things that make the password easy to spot. These are factors like having dictionary words within the password or having the same letter multiple times. The dictionary works by using a plain text file containing a bunch of words, if any are found then it takes away from the total score. The maximum score a password can get is 100, and if any problems are found then this value is subtracted.

The scoring of passwords does not look at what validation factors have been put in place, it simply looks for best practices in password creation. To score a password use the score() function like this:

$password = new Password();
$score = $password->scorePassword('wound33oo#_Xu3!');

The creation of random valid passwords is done through the use of the generatePassword() function. This function looks at the different values set in the object and creates a string that passes validation for those parameters. This is how to create the random password.

$password = new Password();
$password = $password->generatePassword();

This will generate a string like #7xWq#J6. If you want to get a different password just call generatePassword() again. Every return value from this function should be different, unless the parameters have been severly restricted.

Feel free to give the Password class a run. It has been quite well tested, but there might be issues that I have overlooked so if you find anything then please let me know.