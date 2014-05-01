<?php
/**
 * 
 * This class is used to encrypt/decrypt sensitive values using AES256 CBC encryption/decryption standard + hashMac (Hash-based message authentication code) to avoid several tricky exploit such as 
 *  http://en.wikipedia.org/wiki/Padding_oracle_attack
 *  http://en.wikipedia.org/wiki/Bit-flipping_attack
 * 
 * Could be a string or a serializable object
 * 
 * Sensitive data should be encrypted, and one of the most popular encryption specifications is the Advanced Encryption Standard (AES).
 * The AES specification, using the Rijndael algorithm, has been selected as the replacement for the 3DES algorithm that is implemented by Yii’s CSecurityManger.
 * We used CBC mode because it is more secured than ECB mode as it creates a different has each time.
 * 
 * To implement AES for your project :
 * - add aes256 extension into your /config/main.php, in the components part. Sample : 
 * 		'aes256'=>array(
 *        	'class' => 'application.extensions.aes256.Aes256',
 *       	'privatekey_32bits_hexadecimal'=> '0123456789012345678901234567890123456789012345678901234567890123', // be sure that this parameter uses EXACTLY 64 chars of hexa (a-f, 0-9)
 *       ),
 *              
 * - include the method decrypt in your model in afterFind() and encrypt in beforeSave().  
 * - Don't forget that search() model method won't work on encrypted data neither specific SQL queries dealing with encrypted fields.
 *    So don't forget that if you are using specific SQL query results (outside Yii ActiveRecord) you will have to encrypt/decrypt database field manually
 * 
 *  - Don't forget that encrypted string value could be long. Avoid short database row VARCHAR(256) for example (to avoid truncated encrypted value that won't be decryptable). 
 *     Personnaly, i'm using **TEXT** type or **VARCHAR(3000)**. 

 * @property privatekey_32bits_hexadecimal private key that must be EXACTLY 64 characters length of hexa (a-f, 0-9)
 * 
 * @author Luc Bonnin <luc@revelis.fr - comments + refactor for yii extension
 * @author Inspired by joshhartman version https://gist.github.com/joshhartman/5383582#file-mcrypt-cbc-php
 */
class Aes256 extends CApplicationComponent{
	
	/**
	 * Use of AES256 with mcrypt lib
	 * @var string
	 */
	const MCRYPT_CYPHER = MCRYPT_RIJNDAEL_128;
	/**
	 * 
	 * Use CBC mcrypt lib mode as it is more secured than EBC (because it creates a different hash each time)
	 * @var string
	 */
	const MCRYPT_MODE   = MCRYPT_MODE_CBC;
	
	/**
	 * Use self::MCRYPT_IV_SOURCE as IV source (read data from /dev/urandom). From PHP5.3 it is not required to use srand().
	 * @var int
	 */
	const MCRYPT_IV_SOURCE = MCRYPT_DEV_URANDOM;
	
	/**
	 * Private encryption/decryption key (only hexa (a-f, 0-9))
	 * /config/main.php extension parameter.
	 * Sample value : 'd0a7e7997b6d5fcd55f4b5c32611b87cd923e88837b63bf2941ef819dc8ca666' 
	 * @var string must be strlen=64
	 */
	public $privatekey_32bits_hexadecimal = '';   

	
	/**
	 * Initialize Yii extension
	 * Will check to see if mcrypt is enabled and the parameter used is a valid one
	 */
	public function init()
	{
		if( !function_exists( 'mcrypt_module_open') )
			throw new CException( Yii::t('aes256', 'You must have mcrypt lib enable on your server to be enabled to use this extension.') );

		if(empty($this->privatekey_32bits_hexadecimal) || strlen($this->privatekey_32bits_hexadecimal)!=64)
			throw new CException(Yii::t('aes256','aes256 extension parameter privatekey_32bits_hexadecimal must be filled with exactly 64 hexadecimal characters !'));
	}

	
	/**
	 * Encrypt input data using AES256 CBC encryption
	 * @param unknown_type $dataToEncrypt Data to encrypt. Could be a string or a serializable PHP object
	 * @return string Return encrypted AES256 CBC value
	 */
	public function encrypt($dataToEncrypt)
	{
	 	// 1- serialize data to encrypt. Could be a string or a serializable object
		$result = serialize($dataToEncrypt);
		
		// 2- Create randomize IV using RIJNDAEL_256 AND CBC mode. CBC is more secured than EBC because it creates a different hash each time
		$iv = mcrypt_create_iv(mcrypt_get_iv_size(self::MCRYPT_CYPHER, self::MCRYPT_MODE), self::MCRYPT_IV_SOURCE);
		
		// 3- Pack private key and create hmac hash to be able to add integrity check while decrypt data
		$key = $this->_buildKey();
		$mac = hash_hmac('sha256', $result, substr(bin2hex($key), -32));
		
		// 4- Encrypt data
		$result = mcrypt_encrypt(self::MCRYPT_CYPHER, $key, $result.$mac, self::MCRYPT_MODE, $iv);
		
		// 5- Encode encrypted data using base64 for standardization (compatibilities purpose between php server and database for example to avoid loosing encrypted weird data).
		//    Keep encrypted data + iv to be able to decrypt it
		$result = base64_encode($result).'|'.base64_encode($iv);
		return $result;
	}
 
	/**
	 * 
	 * Decrypt encrypted string.
	 * @param string $encryptedString Encrypted string to decrypt
	 * @param bool $bReturnFalseIfError false by default. If TRUE, return false in case of error (bad decryption). Else, return given $encryptedInput value
	 * @return string Return decrypted value (string or unsezialized object) if suceeded. Return FALSE if an error occurs (bad password/salt given) or inpyt encryptedString
	 */
	public function decrypt($encryptedString,$bReturnFalseIfError=false)
	{			 	
	 	// 1- Split encrypted string value and iv
		$decrypt = explode('|', $encryptedString);
		
		// 2- Check if given value was not encrypted using  encrypt method (because no '|' found)
		if(count($decrypt)!=2){
			return $bReturnFalseIfError?false:$encryptedString;				
		}
		
		// 3- Decode both parts
		$decoded = base64_decode($decrypt[0]);
		$iv = base64_decode($decrypt[1]);
		
		// 4- Pack private key :
		$key = $this->_buildKey();
		
		// 5- Decrypt serialized value using RIJNDAEL_256 AND CBC mode. CBC is more secured than EBC because it creates a different hash each time
		$decrypted = trim(mcrypt_decrypt(self::MCRYPT_CYPHER, $key, $decoded, self::MCRYPT_MODE, $iv));
		
		// 6- Retrieve mac and calcmac for integrity check
		$mac = substr($decrypted, -64);
		$decrypted = substr($decrypted, 0, -64);
		$calcmac = hash_hmac('sha256', $decrypted, substr(bin2hex($key), -32));
		
		// 7- Check if decrypted string was truly (previously) encrypted with the same private key
		if($calcmac!==$mac){
			throw new CException(Yii::t('aes256','Decrypted value was not previously encrypted using the same private key. Please check that used private key is relevant or that given encryptedString was not corrupted')); 
			//return $bReturnFalseIfError?false:$encryptedString;
		}
		
		// 8- Unserialized decrypted value
		$decrypted = unserialize($decrypted);
		
		 // Yipikai yeah !		
		return $decrypted;
	}	    
	
	/**
	 * Build packed private key that will be used by encrypt/decrypt method
	 */
	private function _buildKey()
	{
		return pack('H*',$this->privatekey_32bits_hexadecimal);				
	}
}
