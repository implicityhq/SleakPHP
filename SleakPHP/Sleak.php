<?
// The MIT License (MIT)

// Copyright (c) 2014 Jason Silberman

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

/**
 * Sleak Helper Functions
 */

function array_keys_to_lower($array) {
  $rr = [];
  foreach ($array as $k => $v) {
    $rr[strtolower($k)] = $v;
  }
  return $rr;
}

function normalizeAuthenticationData($authorizationData) {
  return str_replace(['<', '>'], '', $authorizationData);
}

function normalizeAuthenticationInfo($authInfo) {
  $infoDictionary = [];
  foreach ($authInfo as $authPiece) {
    $parts = explode('=', $authPiece);
    $key = trim(array_shift($parts));
    $value = trim(str_replace('"', '', array_shift($parts)));
    $infoDictionary[$key] = $value;
  }
  return $infoDictionary;
}

function normalizeParameterData($array) {
  foreach ($array as $k => $v) {
      if (preg_match('/([^a-zA-Z0-9\-\_])/', $k)) {
        unset($array[$k]);
      } else if ($v === 0) {
        $array[$k] = false; 
      }
    }
    return $array;
}

/**
 * Sleak Exception
 */

class SleakException extends Exception {
  const SLEAK_Invalid_Digest = 1;
  const SLEAK_Already_Used = 2;
  const SLEAK_User_Error = 3;
}

/**
 * Sleak Response
 */

class SleakResponse {
  public $ok, // Bool
         $errorCode, // string (already_used|invalid_digest|unabled_to_complete)
         $message; // string

  public function __construct($ok = true, $errorCode = null, $message = null) {
    $this->ok = $ok;
    $this->errorCode = $errorCode;
    $this->message = $message;
    return $this;
  }
}

/**
 * Sleak
 */

class Sleak {
  const SLEAK_App_Id_Key = 'x-sleak-application-id';
  const SLEAK_Timestamp_Key = 'x-sleak-timestamp';
  const SLEAK_Nonce_Key = 'x-sleak-nonce';
  const SLEAK_Scheme = 'Sleak';
  const SLEAK_Authorization_Key = 'authorization';

  protected $privateKeyCallback, $fetchReplayCallback, $insertReplayCallback;

  public function setPrivateKeyLookupCallback($lookupCallback) {
    if (is_callable($lookupCallback)) {
      $this->privateKeyCallback = $lookupCallback;
    } else {
      throw new SleakException('Invalid private key lookup callback provided.', SleakException::SLEAK_User_Error);
    }
  }

  public function setFetchReplayCallback($replayCallback) {
    if (is_callable($replayCallback)) {
      $this->fetchReplayCallback = $replayCallback;
    } else {
      throw new SleakException('Invalid fetch replay callback provided.', SleakException::SLEAK_User_Error);
    }
  }

  public function setInsertReplayCallback($replayCallback) {
    if (is_callable($replayCallback)) {
      $this->insertReplayCallback = $replayCallback;
    } else {
      throw new SleakException('Invalid insert replay callback provided.', SleakException::SLEAK_User_Error);
    }
  }

  public function run($fatal = true) {
    return $this->handleAuth(
      array_keys_to_lower(getallheaders())[self::SLEAK_Authorization_Key],
      array_keys_to_lower(getallheaders())[self::SLEAK_App_Id_Key],
      (bool) $fatal
    );
  }

  protected function handleAuth($completeAuthHeader, $applicationId, $fatal) {
    $authHeaderParts = explode(',', $completeAuthHeader);
    $authHeader = array_shift($authHeaderParts);

    $authInfoDictionary = normalizeAuthenticationInfo($authHeaderParts);

    $authParts = explode(' ', $authHeader);
    $scheme = array_shift($authParts);

    $nonce = $authInfoDictionary['auth_nonce'];
    $timestamp = $authInfoDictionary['auth_timestamp'];

    $nonceAlreadyExists = call_user_func_array($this->fetchReplayCallback, [$nonce, $timestamp]);

    if ($nonceAlreadyExists) {
      if ($fatal) {
        throw new SleakException('Unable to continue.', SleakException::SLEAK_Already_Used);
      }

      return (new SleakResponse(false, 'already_used', 'Previously used nonce/timestamp.'));
    } else {
      call_user_func_array($this->insertReplayCallback, [$nonce, $timestamp]);
    }

    $authData = normalizeAuthenticationData(implode('', $authParts));

    $privateKey = call_user_func_array($this->privateKeyCallback, [$applicationId]);

    $requestVars = null;

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
      $requestVars = $_POST;
    } else if ($_SERVER['REQUEST_METHOD'] === 'GET') {
      $requestVars = $_GET;
    } else {
      if ($fatal) {
        throw new SleakException('Invalid request method.', SleakException::SLEAK_User_Error);
      }

      return (new SleakResponse(false, 'unabled_to_complete', 'Invalid request method.'));
    }

    $params = normalizeParameterData($requestVars);
    ksort($params);
    $params[self::SLEAK_App_Id_Key] = $applicationId;
    $params[self::SLEAK_Timestamp_Key] = $timestamp;
    $params[self::SLEAK_Nonce_Key] = $nonce;

    $paramString = http_build_query($params);
    $hmacData = hash_hmac('sha256', $paramString, $privateKey);
    if ($authData !== $hmacData) {
      if ($fatal) {
        throw new SleakException('Unable to continue.', SleakException::SLEAK_Invalid_Digest);
      }

      return (new SleakResponse(false, 'invalid_digest', 'Invalid digest provided.'));
    } else {
      return (new SleakResponse);
    }
  }
}
