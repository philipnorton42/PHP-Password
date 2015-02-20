<?php
/**
 * This file contains the class Password.
 * For more information on this file and how to use the class please visit
 * http://www.hashbangcode.com/blog/password-validation-class-in-php-2015.html
 *
 * PHP Version 5.0.0
 *
 * @category Password
 * @package  Password
 * @author   Philip Norton <philipnorton42@gmail.com>
 * @license  http://www.gnu.org/copyleft/gpl.html GNU General Public License
 * @link     http://www.hashbangcode.com/
 */
namespace PHPPassword;

/**
 * This class can be used to validate a password or password like string to
 * certain standards. These can be things like having more than one letter,
 * or having at least a single number.
 * The class can also be used to "score" a password to certain parameters.
 *
 * @category Password
 * @package  Password
 * @author   Philip Norton <philipnorton42@gmail.com>
 * @license  http://www.gnu.org/copyleft/gpl.html GNU General Public License
 * @version  Release: 1.0 04/09/2009
 * @link     https://github.com/philipnorton42/PHP-Password
 *
 */
class Password {

  /**
   *
   * @var array Holds an array of any errors encountered whilst validating
   *            the password.
   */
  protected $errors = array();

  /**
   *
   * @var integer The minimum number of characters that the password must be.
   */
  protected $minLength = 7;

  /**
   *
   * @var integer The maximum number of characters that the password must be.
   */
  protected $maxLength = 15;

  /**
   *
   * @var integer The minimum number of numbers that the password should contain.
   */
  protected $minNumbers = 1;

  /**
   *
   * @var integer The minimum number of letters that the password should contain.
   */
  protected $minLetters = 5;

  /**
   *
   * @var integer The minimum number of lower case letters that the password
   *              should contain.
   */
  protected $minLowerCase = 1;

  /**
   *
   * @var integer The minimum number of upper case letters that the password
   *              should contain.
   */
  protected $minUpperCase = 1;

  /**
   *
   * @var integer The minimum number of symbols that the password should contain.
   */
  protected $minSymbols = 1;

  /**
   *
   * @var integer The maximum number of symbols that the password should contain.
   */
  protected $maxSymbols = 3;

  /**
   *
   * @var array The symbols that are allowed to be in the password.
   */
  protected $allowedSymbols = array('#', '_', '!');

  /**
   *
   * @var integer The score of the password.
   */
  protected $score = 100;

  /**
   * Constructor
   *
   * @param array $options An associative array of options.
   */
  public function __construct($options = array()) {
    // Pass options setting onto the setOptions() function.
    $this->setOptions($options);
  }

  /**
   * Validate the password to the defined parameters. If a parameters is not
   * set at runtime then a default value is used.
   *
   * @param string $password The password.
   *
   * @return boolean True if password valid, otherwise false.
   */
  public function validatePassword($password) {
    // Make sure that parameters don't overlap in such a way as to make
    // validation impossible.
    $this->_sanitizeInputs();

    $this->errors = array();

    // Check password minimum length, return at this step.
    if (strlen($password) < $this->minLength) {
      $this->errors[] = 'Password must be ' . $this->minLength . ' characters long, current password is too short at ' . strlen($password) . ' characters.';
      return false;
    }
    // Check password maximum length, return at this step.
    if (strlen($password) > $this->maxLength) {
      $this->errors[] = 'Password must be ' . $this->minLength . ' characters long, current password is too long at ' . strlen($password) . ' characters.';
      return false;
    }
    // Check the number of numbers in the password.
    if (strlen(preg_replace('/([^0-9]*)/', '', $password)) < $this->minNumbers) {
      $this->errors[] = 'Not enough numbers in password, a minimum of ' . $this->minNumbers . ' required.';
    }
    // Check the number of letters in the password
    if (strlen(preg_replace('/([^a-zA-Z]*)/', '', $password)) < $this->minLetters) {
      $this->errors[] = 'Not enough letters in password, a minimum of ' . $this->minLetters . ' required.';
    }
    // Check the number of lower case letters in the password
    if (strlen(preg_replace('/([^a-z]*)/', '', $password)) < $this->minLowerCase && $this->minLowerCase != 0) {
      $this->errors[] = 'Not enough lower case letters in password, a minimum of ' . $this->minLowerCase . ' required.';
    }
    // Check the number of upper case letters in the password
    if (strlen(preg_replace('/([^A-Z]*)/', '', $password)) < $this->minUpperCase && $this->minUpperCase != 0) {
      $this->errors[] = 'Not enough upper case letters in password, a minimum of ' . $this->minUpperCase . ' required.';
    }
    // Check the minimum number of symbols in the password.
    if (strlen(preg_replace('/([a-zA-Z0-9]*)/', '', $password)) < $this->minSymbols && $this->maxSymbols != 0) {
      $this->errors[] = 'Not enough symbols in password, a minimum of ' . $this->minSymbols . ' required.';
    }
    // Check the maximum number of symbols in the password.
    if (strlen(preg_replace('/([a-zA-Z0-9]*)/', '', $password)) > $this->maxSymbols) {
      if ($this->maxSymbols == 0) {
        $this->errors[] = 'You are not allowed any symbols in password, please remove them.';
      } else {
        $this->errors[] = 'Too many symbols in password.';
      }
    }

    // Check that the symbols present in the password are allowed.
    if ($this->maxSymbols != 0) {
      $symbols = preg_replace('/([a-zA-Z0-9]*)/', '', $password);
      for ($i = 0; $i < strlen($symbols); ++$i) {
        if (!in_array($symbols[$i], $this->allowedSymbols)) {
          $this->errors[] = 'Non specified symbol ' . $symbols[$i] . ' used in password, please use one of ' . implode('', $this->allowedSymbols) . '.';
        }
      }
    }

    // If any errors have been encountered then return false.
    if (count($this->errors) > 0) {
      return false;
    }
    return true;
  }

  /**
   * Score the password based on the level of security. This function doesn't
   * look at the parameters set up and simply scores based on best practices.
   * The function first makes sure the password is valid as there is no
   * point in scoring a password that can't be used.
   *
   * @param string $password The password to score.
   *
   * @return mixed Returns an integer score of the password strength.
   */
  public function scorePassword($password) {
    // Make sure password is valid.
    if (!$this->validatePassword($password)) {
      return 0;
    }

    if ($password == '') {
      $this->score = 0;
      return $this->score;
    }

    // Reset initial score.
    $this->score = 100;

    $passwordLetters = preg_replace('/([^a-zA-Z]*)/', '', $password);
    $letters = array();
    for ($i = 0; $i < strlen($passwordLetters); ++$i) {
      // Reduce score for duplicate letters.
      if (in_array($passwordLetters[$i], $letters)) {
        $this->score = $this->score - 5;
      }
      // Reduce score for duplicate letters next to each other.
      if (isset($passwordLetters[$i - 1]) && $passwordLetters[$i] == $passwordLetters[$i - 1]) {
        $this->score = $this->score - 10;
      }
      $letters[] = $passwordLetters[$i];
    }

    // Reduce score for duplicate numbers.
    $passwordNumbers = preg_replace('/([^0-9]*)/', '', $password);
    $numbers = array();
    for ($i = 0; $i < strlen($passwordNumbers); ++$i) {
      if (in_array($passwordNumbers[$i], $numbers)) {
        $this->score = $this->score - 5;
      }
      $numbers[] = $passwordNumbers[$i];
    }

    // Reduce score for no symbols.
    if (strlen(preg_replace('/([a-zA-Z0-9]*)/', '', $password)) == 0) {
      $this->score = $this->score - 10;
    }

    // Reduce score for words in dictionary used in password.
    $dictionary = dirname(__FILE__) . '/words.txt';
    if (file_exists($dictionary)) {
      $handle = fopen($dictionary, "r");

      $words = '';

      while (!feof($handle)) {
        $words .= fread($handle, 8192);
      }

      fclose($handle);

      $words = explode("\n", $words);
      foreach ($words as $word) {
        if (preg_match('/.*?' . trim($word) . '.*?/i', $password, $match)) {
          $this->score = $this->score - 20;
        }
      }
    }

    if ($this->score < 0) {
      $this->score = 0;
    }

    // Return the score.
    return $this->score;
  }

  /**
   * Use the options set up in the class to create a random password that passes
   * validation. This uses certain practices such as not using the letter o or
   * the number 0 as these can be mixed up.
   *
   * @return string The generated password.
   */
  public function generatePassword() {
    // Make sure that parameters don't overlap in such a way as to make
    // validation impossible.
    $this->_sanitizeInputs();

    // Initialise variable.
    $password = '';

    // Add lower case letters.
    $lowerLetters = 'aeiubdghjmnpqrstvxyz';
    if ($this->minLowerCase != 0) {
      for ($i = 0; $i < $this->minLowerCase; ++$i) {
        $password .= $lowerLetters[(rand() % strlen($lowerLetters))];
      }
    }

    // Add upper case letters.
    $upperLetters = 'AEUBDGHJLMNPQRSTVWXYZ';
    if ($this->minUpperCase != 0) {
      for ($i = 0; $i < $this->minUpperCase; ++$i) {
        $password .= $upperLetters[(rand() % strlen($upperLetters))];
      }
    }

    // Add letters.
    if (($this->minLowerCase + $this->minUpperCase) < ($this->minLetters)) {
      $password .= $lowerLetters[(rand() % strlen($lowerLetters))];
    }

    // Add numbers.
    $numbers = '23456789';
    if ($this->minNumbers != 0) {
      for ($i = 0; $i < $this->minNumbers; ++$i) {
        $password .= $numbers[(rand() % strlen($numbers))];
      }
    }

    // Add symbols using the symbols array.
    if ($this->maxSymbols != 0) {
      $symbols = implode('', $this->allowedSymbols);
      if ($this->minSymbols != 0 && strlen($symbols) > 0) {
        for ($i = 0; $i < $this->minSymbols; ++$i) {
          $password .= $symbols[(rand() % strlen($symbols))];
        }
      }
    }

    // If the created password isn't quite long enough then add some lowercase
    // letters to the password string.
    if (strlen($password) < $this->minLength) {
      while (strlen($password) < $this->minLength) {
        $password .= $lowerLetters[(rand() % strlen($lowerLetters))];
      }
    }

    // Shuffle the characters in the password.
    $password = str_shuffle($password);

    // Return the password string.
    return $password;
  }

  /**
   * Set multiple options for the object in one go.
   *
   * @param array $options An associative array of options.
   *
   * @return null
   */
  public function setOptions($options) {
    if (isset($options['maxLength'])) {
      $this->maxLength = $options['maxLength'];
    }

    if (isset($options['minLength'])) {
      $this->minLength = $options['minLength'];
    }

    if (isset($options['minNumbers'])) {
      $this->minNumbers = $options['minNumbers'];
    }

    if (isset($options['minLetters'])) {
      $this->minLetters = $options['minLetters'];
    }

    if (isset($options['minSymbols'])) {
      $this->minSymbols = $options['minSymbols'];
    }

    if (isset($options['maxSymbols'])) {
      $this->maxSymbols = $options['maxSymbols'];
    }

    if (isset($options['allowedSymbols'])) {
      if (is_array($options['allowedSymbols'])) {
        $this->allowedSymbols = $options['allowedSymbols'];
      }
    }

    if (isset($options['minLowerCase'])) {
      $this->minLowerCase = $options['minLowerCase'];
    }

    if (isset($options['minUpperCase'])) {
      $this->minUpperCase = $options['minUpperCase'];
    }
    // Make sure that parameters don't overlap in such a way as to make
    // validation impossible.
    $this->_sanitizeInputs();
  }

  /**
   * Get any errors produced through the last validation.
   *
   * @return array
   */
  public function getErrors() {
    return $this->errors;
  }

  /**
   * Get the maximum length of password allowed.
   *
   * @param integer $maxLength The maximum length of password allowed.
   *
   * @return null
   */
  public function setMaxLength($maxLength) {
    $this->maxLength = $maxLength;
  }

  /**
   * The maximum character length of the password.
   *
   * @return integer The maximum character length of the password.
   */
  public function getMaxLength() {
    return $this->maxLength;
  }

  /**
   * The minimum character length of the password.
   *
   * @return integer The minimum character length of the password.
   */
  public function getMinLength() {
    return $this->minLength;
  }

  /**
   * Get the minimum length of password allowed.
   *
   * @param integer $minLength The minimum length of password allowed.
   *
   * @return null
   */
  public function setMinLength($minLength) {
    $this->minLength = $minLength;
  }

  /**
   * The minimum letter count in the password.
   *
   * @return integer The minimum letter count in the password.
   */
  public function getMinLetters() {
    return $this->minLetters;
  }


  /**
   * Get the symbols allowed in password.
   *
   * @return array The allowed symbols array.
   */
  public function getAllowedSymbols() {
    return $this->allowedSymbols;
  }

  /**
   * An array of symbols that can be included in the password. If an array is
   * not passed to this function then it is not stored.
   *
   * @param array|string $symbols An array of symbols that can be included in the
   *                       password. This can be a string, which will be parsed
   *                       into an array of symbols.
   *
   * @return null
   */
  public function setAllowedSymbols($symbols) {
    if (!is_array($symbols)) {
      $symbols = preg_split('//', $symbols);
    }

    // Filter the symbols to remove any non symbol characters.
    $symbols = array_filter($symbols, array($this, 'filterAllowedSymbols'));

    if (is_array($symbols)) {
      $symbols = array_unique($symbols);
      $this->allowedSymbols = $symbols;
    }
  }

  /**
   * Callback function for setAllowedSymbols() to allow non symbol characters to be
   * filtered out of the symbols array upon insertion.
   *
   * @param mixed The array item to inspect.
   *
   * @return boolean False if the item is a symbol, otherwise true.
   */
  protected function filterAllowedSymbols($character) {
  	if (preg_match('/[^a-zA-Z0-9 ]/', $character) == 1) {
  		return 1;
  	} else {
  	    return 0;
  	}
  }

  /**
   * Set the minimum number of symbols required in the password.
   *
   * @param integer $minSymbols The minimum number of symbols.
   *
   * @return null
   */
  public function setMinSymbols($minSymbols) {
    $this->minSymbols = $minSymbols;
  }

  /**
   * Get the minimum number of symbols required in the password.
   *
   * @return integer The minimum number of symbols.
   */
  public function getMinSymbols() {
    return $this->minSymbols;
  }

  /**
   * Get the minimum number of upper case letters required in the password.
   *
   * @return integer The minimum number of upper case letters.
   */
  public function getMinUpperCase() {
    return $this->minUpperCase;
  }

  /**
   * Get the minimum number of lower case letters required in the password.
   *
   * @return integer The minimum number of lower case letters.
   */
  public function getMinLowerCase() {
    return $this->minLowerCase;
  }

  /**
   * Set the maximum number of symbols required in the password.
   *
   * @param integer $maxSymbols The maximum number of symbols.
   *
   * @return null
   */
  public function setMaxSymbols($maxSymbols) {
    $this->maxSymbols = $maxSymbols;
  }

  /**
   * The maximum number of symbols allowed in the password.
   *
   * @return integer The maximum number of symbols allowed in the password.
   */
  public function getMaxSymbols() {
    return $this->maxSymbols;
  }

  /**
   * Make sure that parameters don't overlap in such a way as to make
   * validation impossible. For example, if the minimum number of letters
   * numbers and symbols allowed is greater than the maximum length of the
   * password then these numbers are added together and used as the new maximum
   * password length.
   *
   * @return null
   */
  private function _sanitizeInputs() {
    $minPosLength = $this->minNumbers + $this->minLetters + $this->minSymbols;

    if ($minPosLength > $this->minLength) {
      $this->minLength = $minPosLength;
    }

    if ($this->minLength > $this->maxLength) {
      $this->minLength = $this->maxLength;
    }

    if ($this->minSymbols > $this->maxSymbols) {
      $this->minSymbols = $this->maxSymbols;
    }
  }

}
