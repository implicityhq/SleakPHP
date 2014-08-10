SleakPHP
=========

A standard library for using Sleak in PHP.

## Usage
To use SleakPHP you need version `>= 5.4`. If you have lower than `5.4` SleakPHP will throw many errors.

Using SleakPHP is pretty simple:

```php
$sleak = new Sleak();

$sleak->setPrivateKeyLookupCallback(function ($applicationId) {
  return PRIVATE_KEY; // look up private key using $applicationId
});
$sleak->setFetchReplayCallback(function ($nonce, $timestamp) {
  return BOOL; // run check to see if $nonce/$timestamp have been used before
});
$sleak->setInsertReplayCallback(function ($nonce, $timestamp) {
  // insert $nonce/$timestamp into DB somewhere
});

$sleakResponse = $sleak->run(false); // true if Sleak should throw exceptions
if ($sleakResponse->ok === true) {
  // Sleak auth was a success & shuold execute given request
} else {
  // Sleak auth failed
  print 'Failed.' . PHP_EOL;
  print 'Reason: [' . $sleakResponse->errorCode . '] ' . $sleakResponse->message;
}
```