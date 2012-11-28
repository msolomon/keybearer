# Keybearer

Keybearer uses several independent passwords to encrypt a file and later requires a subset of those passwords to decrypt it.

All operation are performed in client-side Javascript.

You can check out a [live version](http://michael-solomon.net/keybearer/) at my site.

## Example

For example, Magician Mike uses Keybearer to encrypt the password to his laptop containing his secret repertoire of tricks. He gives the 3 passcodes he used to his estranged siblings Alice, Bob, and Charlie, on the condition that at least 2 of them reunite on his death to gaze on the majesty of his secrets.

After Magician Mike is tragically sawed in half by his careless assistant, Alice and Bob meet to decrypt Mike's files using their passcodes. They are reunited through their Keybearer experience, while Charlie maintains his grudge and burns his passcode with fire.

## Known issues
* Web workers and the File Reader API must be supported by the browser for Keybearer to function
* Most browsers apart from Chrome don't support the 'download' attribute, and won't download the files using the proper names
* Most browsers apart from Chrome don't supply decent random numbers to Javascript, and so require mouse movement for random data
* The code (especially kbpage.js) is not as beautiful as I would like. This is my first Javascript project, so sorry about being so tightly bound with the DOM in the example

## Notes on operation
* Whitespace is stripped from each end of each password
* Whitespace inside passwords is collapsed down to a single space
* Encryption is done in a web worker
* Decryption is done in the main thread
* Randomized passwords are generated from a list of 50,000 common English words
