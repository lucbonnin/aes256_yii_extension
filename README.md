aes256_yii_extension
====================

This extension is a usefull class that let you encrypt/decrypt string (or object serializable) using strong AES256 (Advanced Encryption Standard with a key of 256 bits) standard with CBC + hashMac (mash-based message authentification code).
Requirements

Yii 1.1 or above PHP 5.3 or above
Usage

To implement AES for your project : - copy Aes256.php into a new folder in /protected/extensions/aes256/Aes256.php - add aes256 extension into your /config/main.php, in the component part. Sample :

[...]
'components'=>array(
    'aes256'=>array(
            'class' => 'application.extensions.aes256.Aes256',
            'privatekey_32bits_hexadecimal'=> '0123456789012345678901234567890123456789012345678901234567890123', // be sure that this parameter uses EXACTLY 64 chars of hexa (a-f, 0-9)
        ),
 
[...]
)

    include the method decrypt in your model in afterFind() and encrypt in beforeSave(). Sample :

protected function afterFind()
{
    // decrypt myEncrypted Field value that is encrypted database side
    $this->myEncryptedField = Yii::app()->aes256->decrypt($this->myEncryptedField);
 
    return parent::afterFind();
}
 
 
protected function beforeSave()
{
    $result = parent::beforeSave();     
    if(!$result) return false;
 
    // encrypt myEncrypted Field value
    $this->myEncryptedField = Yii::app()->aes256->encrypt($this->myEncryptedField);
 
    return $result;
}

    Don't forget that search() model method won't work on encrypted data neither specific SQL queries dealing with encrypted fields. So don't forget that if you are using specific SQL query results (outside Yii ActiveRecord) you will have to encrypt/decrypt database field manually

    Don't forget that encrypted string value could be long. Avoid short database row VARCHAR(256) for example (to avoid truncated encrypted value that won't be decryptable). Personnaly, i'm using TEXT type or VARCHAR(3000).

Resources

Sensitive data should be encrypted, and one of the most popular encryption specifications is the Advanced Encryption Standard (AES).

The AES specification, using the Rijndael algorithm, has been selected as the replacement for the 3DES algorithm that is implemented by Yii’s CSecurityManger.

We used CBC mode because it is more secured than ECB mode as it creates a different has each time.

We also used hashMac (Hash-based message authentication code) to avoid several hacking exploits such as : padding oracle attach http://en.wikipedia.org/wiki/Padding_oracle_attack or bit flipping attach http://en.wikipedia.org/wiki/Bit-flipping_attack
