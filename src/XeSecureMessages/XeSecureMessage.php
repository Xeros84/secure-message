<?php

/**
 * Class XeSecureMessage
 */
class XeSecureMessage
{
    const encryptionAlgorithm = 'aes-256-cbc';
    const hashAlgorithm = 'sha256';
    const replayTime = 10;

    const method = 'POST';
    const header = 'Content-type: application/x-www-form-urlencoded';

    protected $hash;
    protected $encryptedData;
    protected $apiId;

    public function __construct($hash, $encryptedData, $apiId = null)
    {
        $this->hash = $hash;
        $this->encryptedData = $encryptedData;
        $this->apiId = $apiId;
    }

    public static function newFromPost()
    {
        if (!(isset($_POST['hash']) AND isset($_POST['encryptedData']))) {
            throw new Exception('Invalid input');
        }
        if (isset($_POST['apiId'])) {
            return new XeSecureMessage($_POST['hash'], $_POST['encryptedData'], $_POST['apiId']);
        } else {
            return new XeSecureMessage($_POST['hash'], $_POST['encryptedData'], null);
        }
    }

    public static function newFromGet()
    {
        if (!(isset($_GET['hash']) AND isset($_GET['encryptedData']))) {
            throw new Exception('Invalid input');
        }
        if (isset($_GET['apiId'])) {
            return new XeSecureMessage($_GET['hash'], $_GET['encryptedData'], $_GET['apiId']);
        } else {
            return new XeSecureMessage($_GET['hash'], $_GET['encryptedData'], null);
        }
    }

    public static function newFormPostOrGet()
    {
        if (isset($_POST['hash'])) {
            $hash = $_POST['hash'];
        } elseif (isset($_GET['hash'])) {
            $hash = $_GET['hash'];
        } else {
            throw new Exception('Invalid input');
        }
        if (isset($_POST['encryptedData'])) {
            $encryptedData = $_POST['encryptedData'];
        } elseif (isset($_GET['encryptedData'])) {
            $encryptedData = $_GET['encryptedData'];
        } else {
            throw new Exception('Invalid input');
        }
        if (isset($_POST['apiId'])) {
            $apiId = $_POST['apiId'];
        } elseif (isset($_GET['apiId'])) {
            $apiId = $_GET['apiId'];
        } else {
            $apiId = null;
        }
        return new XeSecureMessage($hash, $encryptedData, $apiId);
    }

    public static function newFromArray(array $xsmArray)
    {
        if (!(isset($xsmArray['hash']) AND isset($xsmArray['encryptedData']))) {
            throw new Exception('Invalid input');
        }
        if (isset($xsmArray['apiId'])) {
            return new XeSecureMessage($xsmArray['hash'], $xsmArray['encryptedData'], $xsmArray['apiId']);
        } else {
            return new XeSecureMessage($xsmArray['hash'], $xsmArray['encryptedData'], null);
        }
    }

    public static function newFromString($xsmString)
    {
        $xsmArray = explode(' ', $xsmString);
        switch (count($xsmArray)) {
            case 3:
                return new XeSecureMessage($xsmArray[0], $xsmArray[1], $xsmArray[2]);
            case 2:
                return new XeSecureMessage($xsmArray[0], $xsmArray[1], null);
            default:
                throw new Exception('Invalid input');
        }
    }

    public function toArray()
    {
        return array(
            'hash'          => $this->hash,
            'encryptedData' => $this->encryptedData,
            'apiId'         => $this->apiId
        );
    }

    public function toString() {
        if ($this->apiId)
        {
            return $this->hash . ' ' . $this->encryptedData . ' ' . $this->apiId;
        } else {
            return $this->hash . ' ' . $this->encryptedData;
        }
    }

    /**
     * Function fromDataArray
     *
     * @param array $data - the data array which shall be encrypted
     * @param $hashKey - applicable hash key
     * @param $encryptionKey - applicable encryption key
     * @param $encryptionIv - applicable encryption iv
     * @param null $apiId - optional api id
     * @return XeSecureMessage
     */
    public static function createFromDataArray(array $data, $hashKey, $encryptionKey, $encryptionIv, $apiId = null)
    {
        // in addition to the data, always transfer a timestamp
        $data = array_merge(array('timestamp' => time()), $data);
        // convert the array to json
        $jsonData = json_encode($data);
        // encrypt the data (and base64 encode)
        $encryptedData = self::base64url_encode(openssl_encrypt($jsonData, self::encryptionAlgorithm, $encryptionKey, 0, $encryptionIv));
        // create a hash key for the data
        $hash = hash_hmac(self::hashAlgorithm, $encryptedData, $hashKey, false);
        // return the encrypted data and hash
        return new XeSecureMessage($hash, $encryptedData, $apiId);
    }

    /**
     * Function verifyUnpackData
     *
     * @param $hashKey - applicable hash key
     * @param $encryptionKey - applicable encryption key
     * @param $encryptionIv - applicable encryption iv
     * @param int $timeDiff - time difference between sender and receiver, in seconds
     * @param bool|true $timeOut - if true, check for timeouts / replay attacks
     * @return array - the originally encrypted data
     * @throws Exception
     */
    public function verifyUnpackData($hashKey, $encryptionKey, $encryptionIv, $apiId = null, $timeDiff = 0, $timeOut = true)
    {
        // if an api id is provided, check whether the message api id matches
        if ($apiId) {
            if ($apiId !== $this->apiId) {
                throw new Exception('Wrong API ID');
            }
        }
        // create hmac hash from encrypted data and the given hash key
        $checkValue = hash_hmac(self::hashAlgorithm, $this->encryptedData, $hashKey, false);
        // check whether the hmac hash matches with the hash provided
        if (!self::hash_equals($checkValue, $this->hash)) {
            throw new Exception('Hash check failed');
        }
        // decrypt and decode all data
        $data = openssl_decrypt(self::base64url_decode($this->encryptedData), self::encryptionAlgorithm, $encryptionKey, 0, $encryptionIv);
        $data = json_decode($data, true);
        if (json_last_error() != JSON_ERROR_NONE) {
            throw new Exception('Invalid data decrypted / JSON decode failed');
        }
        // verify that an array has been received
        if (!is_array($data)) {
            throw new Exception('Decrypted data is not an array');
        }
        // check for timeout / prevent replay attacks
        if ($timeOut) {
            if (!isset($data['timestamp'])) {
                throw new Exception('Timeout check failed, no timestamp available');
            } elseif (time() + $timeDiff - $data['timestamp'] > self::replayTime) {
                throw new Exception('Timeout, possibly replay attack');
            }
        }
        // return the data
        return $data;
    }

    public function submit($url)
    {
        if ($this->apiId) {
            $postData = array('hash' => $this->hash, 'encryptedData' => $this->encryptedData, 'apiId' => $this->apiId);
        } else {
            $postData = array('hash' => $this->hash, 'encryptedData' => $this->encryptedData);
        }
        $queryData = http_build_query($postData);
        $streamOptions = array(
            'http' => array(
                'method'  => self::method,
                'header'  => self::header,
                'content' => $queryData
            )
        );
        $streamContext = stream_context_create($streamOptions);
        return self::newFromString(file_get_contents($url, false, $streamContext));
    }

    /**
     * Function hash_equals
     *
     * This function checks whether the provided strings are equal byte by byte
     * TODO : built-in hash_equals included in PHP 5.6
     *
     * @param $str1 - string one for comparison
     * @param $str2 - string two for comparison
     * @return bool - true if equal, false otherwise
     */
    protected static function hash_equals($str1, $str2)
    {
        if (strlen($str1) != strlen($str2)) {
            return false;
        } else {
            $res = $str1 ^ $str2;
            $ret = 0;
            for ($i = strlen($res) - 1; $i >= 0; $i--) {
                $ret |= ord($res[$i]);
            }
            return !$ret;
        }
    }

    protected static function base64url_encode($data){
        return strtr(base64_encode($data), '+/', '-_');
    }

    protected static function base64url_decode($data) {
        return base64_decode(strtr($data, '-_', '+/'));
    }
}