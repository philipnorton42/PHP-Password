<?php

include('../Password.php');

class PasswordTest extends PHPUnit_Framework_TestCase
{
    protected $objPassword;
    
    public function setUp()
    {
        $this->objPassword = new Password();
    }

    public function testInitialMaxLength()
    {
        $this->assertEquals(15, $this->objPassword->getMaxLength());
    }
 
    public function testInitialMinLength()
    {
        $this->assertEquals(7, $this->objPassword->getMinLength());
    }
    
    public function testInitialLengthSet()
    {
        $objPassword = new Password(array('maxLength' => 8));
        $this->assertEquals(8, $objPassword->getMaxLength());
    }
    
    public function testBlankPassword()
    {
        $result = $this->objPassword->validatePassword('');
        $this->assertFalse($result);
    }

    public function testBooleanPassword()
    {
        $result = $this->objPassword->validatePassword(true);
        $this->assertFalse($result);
    }
    
    public function testSimplePassword()
    {
        $result = $this->objPassword->validatePassword('password');
        $this->assertFalse($result);
    }
    
    public function testSimplePasswordWithNumbers()
    {
        $result = $this->objPassword->validatePassword('p2w3ord2');
        $this->assertFalse($result);
        $this->assertTrue(is_Array($this->objPassword->getErrors()));        
    }

    public function testSimplePasswordWithNumbersAndSymbol()
    {
        $this->assertFalse($this->objPassword->validatePassword('qwasd12!'));
    }
    
    public function testMaxLength()
    {
        $this->objPassword->setMaxLength(3);
        $result = $this->objPassword->validatePassword('Qwasd12!');
        $this->assertFalse($result);
        $this->assertEquals(3, $this->objPassword->getMaxLength());
        // Reset to default
        $this->objPassword->setMaxLength(15);
        $result = $this->objPassword->validatePassword('Qwasd12!');
        $this->assertTrue($result);
    }
    
    public function testMinLength()
    {
        $this->objPassword->setMinLength(2);
        $this->assertEquals(2, $this->objPassword->getMinLength());
        $this->assertFalse($this->objPassword->validatePassword('Qw12'));
        $this->assertEquals(7, $this->objPassword->getMinLength());
    }
    
    public function testAllowedSymbols()
    {
        $this->objPassword->setAllowedSymbols(54643476);
        $this->assertTrue(is_array($this->objPassword->getAllowedSymbols()));
        $this->assertTrue($this->objPassword->validatePassword('ASD23a#z_Xx!'));
        $this->objPassword->setAllowedSymbols(array('$', '%' ,'A' ,'!', '#'));
        $this->assertTrue(is_array($this->objPassword->getAllowedSymbols()));
        $this->assertTrue(in_array('%', $this->objPassword->getAllowedSymbols()));
    }
    
    public function testSetParametersAndTestPassword()
    {
        $objPassword = new Password(array(
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
        $this->assertFalse($objPassword->validatePassword('qASw1asd12!'));
        $this->assertFalse($objPassword->validatePassword('�"$%^�$%�$!')); 
        $this->assertFalse($objPassword->validatePassword('QWEASDFASDFF23452565ty~@{}~@{~@!'));
        $this->assertFalse($objPassword->validatePassword('##[]#[#][]#[]#][,./;#[]-'));
        $this->assertFalse($objPassword->validatePassword('QWERTYQWERTR12345#_![]='));
        $this->assertTrue($objPassword->validatePassword('QWERTYqwerty12345#_![]='));
        $this->assertFalse($objPassword->validatePassword('qwertyqwerty12345#_![]='));
        $this->assertTrue($objPassword->validatePassword('5a74A#2d]G6D[r44Df-g8=H5f*2!')); 
    }

    public function testSetWierdParametersAndTestPassword()
    {
        $objPassword = new Password(array(
                                    'minLength'      => 50,
                                    'maxLength'      => 32,
                                    'minNumbers'     => 5,
                                    'minLetters'     => 5,
                                    'minLowerCase'   => 10,
                                    'minUpperCase'   => 10,
                                    'minSymbols'     => 50,
                                    'maxSymbols'     => 2,
                                    'allowedSymbols' => array('#', '_', '-', '!', '[', ']', '=', '~', '*'),
                                    ));
        $this->assertFalse($objPassword->validatePassword('qASw1asd12!'));
        $this->assertFalse($objPassword->validatePassword('�"$%^�$%�$!')); 
        $this->assertFalse($objPassword->validatePassword('QWEASDFASDFF23452565ty~@{}~@{~@!'));
        $this->assertFalse($objPassword->validatePassword('##[]#[#][]#[]#][,./;#[]-'));
        $this->assertFalse($objPassword->validatePassword('QWERTYQWERTR12345#_![]='));
        $this->assertTrue($objPassword->validatePassword('QWWERWEEERTYeqwewerqwerty12345!#'));
        $this->assertFalse($objPassword->validatePassword('qwertyqwerty12345#_![]='));
        $this->assertFalse($objPassword->validatePassword('5a74A#2d]G6D[r44Df-g8=H5f*2!')); 
    }    
    
    public function testRunSanitizeInputsViaOddParameters()
    {
        $objPassword = new Password(array(
                                    'minLength'      => 5,
                                    'maxLength'      => 500,
                                    'minNumbers'     => 10,
                                    'minLetters'     => 10,
                                    'minLowerCase'   => 10,
                                    'minUpperCase'   => 10,
                                    'minSymbols'     => 10,
                                    'maxSymbols'     => 2,
                                    'allowedSymbols' => array('#', '_', '-', '!', '[', ']', '=', '~', '*'),
                                    ));
        $this->assertEquals(30, $objPassword->getMinLength());
    }    
    
    public function testPasswordScoreWithInValidPass()
    {
        $this->assertFalse($this->objPassword->scorePassword('8sdf7aysd'));
    }
    
    public function testPasswordScore()
    {
        $score = $this->objPassword->scorePassword('wound33oo#_Xu3!');
        $this->assertTrue(is_int($score));
    }

    public function testPasswordNegativeScore()
    {
        $this->objPassword->setMaxLength(100);
        $score = $this->objPassword->scorePassword('thisthatotherwordyesnomaybe33oo#_Xu3!');
        $this->assertTrue($score == 0);
    }

    public function testPasswordScoreNoSumbols()
    {
        $this->objPassword->setMinSymbols(0);
        $score = $this->objPassword->scorePassword('wound33ooXu3');
        $this->assertTrue(is_int($score));
        $this->assertEquals(0, $this->objPassword->getMinSymbols());
    }
    
    public function testMaxSymbols()
    {
        $this->objPassword->setMaxSymbols(54643476);
        $this->assertEquals(54643476, $this->objPassword->getMaxSymbols());
        $this->assertTrue($this->objPassword->validatePassword('ASD23a#z_Xx!'));
        $this->assertTrue($this->objPassword->validatePassword('ASD23!!!az_Xx!'));
        $this->objPassword->setMaxSymbols(3);        
    }
    
    public function testNoSymbols()
    {
        $this->objPassword->setMaxSymbols(0);
        $this->assertEquals(0, $this->objPassword->getMaxSymbols());
        $this->assertTrue($this->objPassword->validatePassword('ASD23azdfdXx'));
        $this->assertFalse($this->objPassword->validatePassword('ASD23!az_Xx!'));
        $this->objPassword->setMaxSymbols(3);  
    }
    
    public function testCreatedPassword()
    {  
        $this->assertTrue(is_string($this->objPassword->generatePassword()));
    
        // Default of this should be to produce a valid password. However, because it is random we need to test lots.
        $this->assertTrue(is_bool($this->objPassword->validatePassword($this->objPassword->generatePassword())));
        $this->assertTrue(is_bool($this->objPassword->validatePassword($this->objPassword->generatePassword())));
        $this->assertTrue(is_bool($this->objPassword->validatePassword($this->objPassword->generatePassword())));
        $this->assertTrue(is_bool($this->objPassword->validatePassword($this->objPassword->generatePassword())));
        $this->assertTrue(is_bool($this->objPassword->validatePassword($this->objPassword->generatePassword())));
        $this->assertTrue(is_bool($this->objPassword->validatePassword($this->objPassword->generatePassword())));
        $this->assertTrue(is_bool($this->objPassword->validatePassword($this->objPassword->generatePassword())));
    }
    
    public function testCreatedPasswordMinLength10()
    {
        $this->objPassword->setMinLength(10);    
        $this->assertTrue(is_string($this->objPassword->generatePassword()));
        $this->assertEquals(10, strlen($this->objPassword->generatePassword()));
    }

    public function testCreatedPasswordMinLength76(){
        $this->objPassword->setMinLength(76);
        $this->assertTrue(is_string($this->objPassword->generatePassword()));
        $this->objPassword->generatePassword();
        $this->assertEquals(15, strlen($this->objPassword->generatePassword()));
    }

    public function testCreatedPasswordMinLength76MaxLength80(){
        $this->objPassword->setMinLength(76);
        $this->objPassword->setMaxLength(1000);
        $this->assertTrue(is_string($this->objPassword->generatePassword()));
        $this->objPassword->generatePassword();
        $this->assertEquals(76, strlen($this->objPassword->generatePassword())); 
    }

    public function testCreatedPasswordStrengthParams()
    {
        $this->assertTrue(is_string($this->objPassword->generatePassword()));
        $this->objPassword->setAllowedSymbols(array('#'));        
        $this->assertTrue(strpos($this->objPassword->generatePassword(), '#') !== false);
        //echo $this->objPassword->generatePassword();
        $this->objPassword->setAllowedSymbols(array('$', '%' ,'A' ,'!', '#'));
        $this->assertTrue(is_string($this->objPassword->generatePassword(9, 3)));
    }
    
    public function testPasswordOfZeroLengthScoresZero() {
    	$this->assertEquals($this->objPassword->validatePassword(''), 0);
    }
    
    public function tearDown()
    {
        $this->objPassword = null;
    }
}
