keybearer = {
    // Public settings
    salt_length: 4, // in words (bytes * 4)
    aes_key_strength: 8, // 4 = 128 bits, 6 = 192, 8 = 256
    aes_cipher_mode: 'ccm', // ccm or ocb2 -- ccm seems to be MUCH faster
    pbkdf2_iterations: 50000, // number of key stretching iterations

    _badngramlist: [],
    _salt: null,
    _plaintext: null, // bitArray of file to be encrypted
    _cipherobj: null, // base64 encoded encrypted data in resultant object
    _passwords: [], // plaintext passwords
    _keys: [], // PBKDF2 strengthened passwords result
    _master: null, // the key that actually encrypts the plaintext
    _filename: null, // the unencrypted filename for use on retrieval
    _filetype: null, // the unencrypted MIME type for use on retrieval
    _nPasswords: null, // number of passwords total
    _nToUnlock: null, // number of passwords needed to unlock
    _lastMetadata: null, // last used metadata object
    // Load the wordlist for password generation

    loadWordlist: function(url, field, callback) {
        var startTime = new Date();
        var endTime;
        var txtFile = new XMLHttpRequest();
        txtFile.open("GET", url, true);
        txtFile.onreadystatechange = function() {
            if (txtFile.readyState == 4 && txtFile.status === 200) {  // When password list loaded
                allText = txtFile.responseText;
                keybearer[field] = txtFile.responseText.split("\n");
                endTime = new Date();
                // use load time to help seed RNG
                sjcl.random.addEntropy(endTime.getTime() - startTime.getTime(), 2, "wordlist." + field + ".loadtime");
                callback();
            }
        };
        txtFile.send();
    },

    // Generate a password from wordlist using given # of words
    makePassword: function(length) {
        var pwd = [];
        var selections = keybearer.randto(keybearer._wordlist.length, length);
        for(var i = 0; i < length; i++){
            pwd[i] = keybearer._wordlist[selections[i]];
        }
        // Ensure no known bad combinations are displayed
        var joined = pwd.join(' ');
        for(i = 0; i < keybearer._badngramlist.length; i++){
            if(joined.indexOf(keybearer._badngramlist[i]) !== -1){
                return keybearer.makePassword(length);
            }
        }
        return joined;
    },

    // Generate array of num integers on [0, end)
    randto: function(end, num) {
        // empirical testing (Chrome 22) shows randomWords returning numbers approximately
        // within the range (-1000000000, 1000000000)
        var maximum = Math.floor(1000000000 / end) * end; // regenerate if outside this
        var restrictRange = function(x){
            x = Math.abs(x);
            if(x >= maximum){ // the (even more) naive approach would skew distribution
                return restrictRange(sjcl.random.randomWords(1)[0]);
            }
            return x % end;
        };
        return sjcl.random.randomWords(num).map(restrictRange);
    },

    // Trim string, and collapse all whitespace between words to single space
    normalizeString: function(string){
        return string.replace(/\s+/g, ' ').replace(/(^\s|\s$)/g, '');
    },

    // Generate salt and store
    makeSalt: function(){
        keybearer._salt = sjcl.random.randomWords(keybearer.salt_length);
    },

    // Generate a key using PBKDF2 given a key (after salt has been generated)
    makeKeyFromPassword: function(password){
        return sjcl.misc.pbkdf2(password,
                                keybearer._salt,
                                keybearer.pbkdf2_iterations,
                                keybearer.aes_key_strength * 32);
    },

    // Generate all possible password combinations needed given password list and number needed
    makeCombinedPasswords: function(passwords, nToUnlock){
        // store nPasswords and nToUnlock for later use
        keybearer._nPasswords = passwords.length;
        keybearer._nToUnlock = nToUnlock;
        // recursively generate combinations (in order)
        var combine = function(passwords, output, prefix, levels_left, start){
            if(levels_left <= 0){
                output.push(prefix.replace(/ /, ''));
            } else {
                for(var i = start; i < passwords.length; i++){
                    combine(passwords, output, [prefix, passwords[i]].join(' '), levels_left - 1, i + 1);
                }
            }
        };

        var combined = [];
        for(var i = 0; i < passwords.length; i++){
            passwords[i] = keybearer.normalizeString(passwords[i]);
        }
        passwords.sort();
        combine(passwords, combined, null, nToUnlock, 0);
        return combined;
    },

    // Generate all key combinations, with progress callback
    makeKeyCombinations: function(passwords, nToUnlock, callback){
        callback = callback || function(x){};
        keybearer._keys = [];
        var combinations = keybearer.makeCombinedPasswords(passwords, nToUnlock);
        callback(0);
        for(var i = 0; i < combinations.length; i++){
            keybearer._keys.push(keybearer.makeKeyFromPassword(combinations[i]));
            callback((i+1)/combinations.length);
        }
        callback(1);
        return keybearer._keys;
    },

    // Generate the encryption key
    makeAESKey: function(){
        keybearer._master = sjcl.random.randomWords(keybearer.aes_key_strength);
    },

    // Generate an object storing metadata
    makeMetadataObject: function(){
        return  { adata: '',
                  iter: keybearer.pbkdf2_iterations,
                  mode: keybearer.aes_cipher_mode,
                  cipher: 'aes',
                  ts: 128,
                  ks: keybearer.aes_key_strength * 32,
                  salt: keybearer._salt,
                  iv: sjcl.random.randomWords(4),
                  v: 1,
                  ct: null,
                  fn: keybearer._filename,
                  ft: keybearer._filetype,
                  nkeys: keybearer._nPasswords,
                  nunlock: keybearer._nToUnlock
                };
    },

    // Decrypt the keys until the master is found
    decryptKeys: function(){
        var success = false;
        // currently, there should only be one key in keybearer._keys
        // in the future, this may change, and it's an array anyway
        for(var i = 0; i < keybearer._keys.length; i++){
            var prp = new sjcl.cipher[keybearer._cipherobj.cipher](keybearer._keys[i]);
            // do a linear search against every key that could hold the master key
            for(var j = 0; j < keybearer._cipherobj.keys.length; j++){
                try {
                    var keyiv = keybearer._cipherobj.keys[j];
                    keybearer._master = sjcl.mode[keybearer._cipherobj.mode].decrypt(prp,
                                                                           keyiv.key,
                                                                           keyiv.iv,
                                                                           keybearer._cipherobj.adata,
                                                                           keybearer._cipherobj.ts);
                    success = true;
                } catch(err) {
                    // this wasn't it. keep going until we get a match
                }
            }
        }
        return success;
    },

    // Decrypt the ciphertext from _cipherobject and store in _plaintext
    decryptCiphertext: function(){
        var prp = new sjcl.cipher[keybearer._cipherobj.cipher](keybearer._master);
        keybearer._plaintext = sjcl.mode[keybearer._cipherobj.mode].decrypt(prp,
                                                                  keybearer._cipherobj.ct,
                                                                  keybearer._cipherobj.iv,
                                                                  keybearer._cipherobj.adata,
                                                                  keybearer._cipherobj.ts);
    },

    // complete encryption process with callback
    encryptWithPasswords: function(passwords, nUnlock, callback){
        keybearer.makeKeyCombinations(passwords, nUnlock, callback);
        keybearer.makeAESKey();
        return keybearer.encryptPlaintext(keybearer._plaintext);
    },

    // Encrypt the plaintext
    encryptPlaintext: function(pt){
        var p = keybearer.makeMetadataObject();
        var ptxt = pt || keybearer._plaintext;
        keybearer._lastMetadata = p;
        var prp = new sjcl.cipher[p.cipher](keybearer._master);
        p.ct = sjcl.mode[p.mode].encrypt(
                                        prp,
                                        ptxt,
                                        p.iv,
                                        p.adata,
                                        p.ts);
        keybearer._cipherobj = p;
        keybearer.augmentWithEncryptedKeys(keybearer._cipherobj);
        return keybearer.getCipherJSON();
    },

    // Add the master key, encrypted by every valid combination of passwords
    augmentWithEncryptedKeys: function(obj){
        var encKeys = [];
        for(var i = 0; i < keybearer._keys.length; i++){
            var iv = sjcl.random.randomWords(4);
            var prp = new sjcl.cipher[obj.cipher](keybearer._keys[i]);
            var key = sjcl.mode[obj.mode].encrypt(
                                                  prp,
                                                  keybearer._master,
                                                  iv,
                                                  '',
                                                  obj.ts);
            encKeys.push({"iv": iv, "key": key});
        }
        obj.keys = encKeys;
        keybearer.shuffle(obj.keys); // shuffle the keys
    },

    // shuffle an array in-place using Fisher-Yates
    shuffle: function(arr) {
        var i = arr.length;
        if (i === 0) return false;
        while (--i) {
            var j = keybearer.randto(i + 1, 1);
            var tempi = arr[i];
            var tempj = arr[j];
            arr[i] = tempj;
            arr[j] = tempi;
        }
        return arr;
    },

    // Turn metadata into relevant metadata + secret data
    changeToSecretData: function(obj){
        obj.pwds = keybearer._passwords; // store the passwords
        // not truly happy about this double conversion
        obj.pt = sjcl.codec.base64.fromBits(keybearer._plaintext);
        delete obj.salt;
        delete obj.iv;
        delete obj.ct;
    },

    // Set our binary file contents
    setPlaintext: function(data, fn, ft){
        keybearer._plaintext = sjcl.codec.bitarrays.toBits(data);
        if(fn) keybearer.setFileName(fn);
        if(ft) keybearer.setFileType(ft);
        return true;
    },

    // Set unencrypted filename
    setFileName: function(fname){
        keybearer._filename = fname;
        return keybearer._filename;
    },

    // Set unencrypted file MIME type
    setFileType: function(ftype){
        keybearer._filetype = ftype;
        return keybearer._filetype;
    },

    // Set the number of PBKDF2 iterations
    setPBKDF2Iterations: function(num){
        keybearer.pbkdf2_iterations = num;
    },

    // Set wordlist
    setWordlist: function(wl){
        keybearer._wordlist = wl;
    },

    // Set badngramwordlist
    setBadNGramList: function(wl){
        keybearer._badngramlist = wl;
    },

    // Get unencrypted filename
    getFileName: function(){
        return keybearer._filename;
    },

    // Get unencrypted file MIME type
    getFileType: function(){
        return keybearer._filetype;
    },

    // Get number of passwords possible
    getNPasswords: function(){
        return keybearer._nPasswords;
    },

    // Get number of passwords possible for decryption
    getNPasswordsDecrypt: function(){
        return keybearer._cipherobj.nkeys;
    },

    // Get number of passwords needed
    getNumToUnlock: function(){
        return keybearer._nToUnlock;
    },

    // Get wordlist
    getWordlist: function(){
        return keybearer._wordlist;
    },

    // Get ngram wordlist
    getBadNGramList: function(){
        return keybearer._badngramlist;
    },

    // Reset generated keys
    resetKeys: function(){
        keybearer._keys = [];
    },

    // checks if data has been loaded
    isPlaintextReady: function(){
        return(keybearer._plaintext !== null);
    },

    // checks if encrypted data has been loaded
    isCipherObjectReady: function(){
        return(keybearer._cipherobj !== null);
    },

    // parses data into our encrypted object
    setCipherJSON: function(data){
        var obj = JSON.parse(data);
        // base64 -> bitArray all necessary base64-encoded fields
        obj.salt = sjcl.codec.base64.toBits(obj.salt);
        obj.iv = sjcl.codec.base64.toBits(obj.iv);
        obj.ct = sjcl.codec.base64.toBits(obj.ct);
        for(var i = 0; i < obj.keys.length; i++){
            obj.keys[i].iv = sjcl.codec.base64.toBits(obj.keys[i].iv);
            obj.keys[i].key = sjcl.codec.base64.toBits(obj.keys[i].key);
        }
        // set keybearer fields from JSON
        // if I structured this nicer, this could be automatic
        keybearer._salt = obj.salt;
        keybearer._nPasswords = obj.nkeys;
        keybearer._nToUnlock = obj.nunlock;
        keybearer.setFileName(obj.fn); // set filename from JSON
        keybearer.setFileType(obj.ft); // set filetype from JSON
        keybearer.setPBKDF2Iterations(obj.iter);
        keybearer._cipherobj = obj;
    },

    // Get the cipherobject
    getCipherJSON: function(){
        // copy the object -- this is fairly gross
        var obj = JSON.parse(JSON.stringify(keybearer._cipherobj));
        // base64 encode output
        for(var i = 0; i < obj.keys.length; i++){
            obj.keys[i].iv = sjcl.codec.base64.fromBits(obj.keys[i].iv);
            obj.keys[i].key = sjcl.codec.base64.fromBits(obj.keys[i].key);
        }
        obj.salt = sjcl.codec.base64.fromBits(obj.salt);
        obj.iv = sjcl.codec.base64.fromBits(obj.iv);
        obj.ct = sjcl.codec.base64.fromBits(obj.ct);
        return JSON.stringify(obj);
    },

    // Get the plaintext converted to a bytearray
    getPlaintext: function(){
        return sjcl.codec.bitarrays.fromBits(keybearer._plaintext);
    },

    // Augment an object with another object
    augment: function(toAug, augger){
        for(var k in augger){
            if(augger.hasOwnProperty(k)){
                toAug[k] = augger[k];
            }
        }
    }

};

// Copied here verbatim from codecBytes.js. Should really recompile sjcl.js instead
sjcl.codec.bytes = {
  /** Convert from a bitArray to an array of bytes. */
  fromBits: function (arr) {
    var out = [], bl = sjcl.bitArray.bitLength(arr), i, tmp;
    for (i=0; i<bl/8; i++) {
      if ((i&3) === 0) {
        tmp = arr[i/4];
      }
      out.push(tmp >>> 24);
      tmp <<= 8;
    }
    return out;
  },
  /** Convert from an array of bytes to a bitArray. */
  toBits: function (bytes) {
    var out = [], i, tmp=0;
    for (i=0; i<bytes.length; i++) {
      tmp = tmp << 8 | bytes[i];
      if ((i&3) === 3) {
        out.push(tmp);
        tmp = 0;
      }
    }
    if (i&3) {
      out.push(sjcl.bitArray.partial(8*(i&3), tmp));
    }
    return out;
  }
};

/** @namespace Arrays of bytes */
sjcl.codec.bitarrays = {
  /** Convert from a bitArray to an ArrayBuffer of uint8 bytes */
  fromBits: function (arr) {
    var bl = sjcl.bitArray.bitLength(arr), i, tmp;
    var ab = new ArrayBuffer(bl/8);
    var out = new Uint8Array(ab);
    for (i=0; i<bl/8; i++) {
      if ((i&3) === 0) {
        tmp = arr[i/4];
      }
      out[i] = (tmp >>> 24);
      tmp <<= 8;
    }
    return out;
  },
  /** Convert from an ArrayBuffer of bytes to a bitArray. */
  toBits: function (ab) {
    var bytes = new Uint8Array(ab);
    var out = [], i, tmp=0;
    for (i=0; i<bytes.length; i++) {
      tmp = tmp << 8 | bytes[i];
      if ((i&3) === 3) {
        out.push(tmp);
        tmp = 0;
      }
    }
    if (i&3) {
      out.push(sjcl.bitArray.partial(8*(i&3), tmp));
    }
    return out;
  }
};
