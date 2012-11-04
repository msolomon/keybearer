keybearer = {
    // Public settings
    salt_length: 4, // in words (bytes * 4)
    aes_key_strength: 8, // 4 = 128 bits, 6 = 192, 8 = 256
    aes_cipher_mode: 'ccm', // ccm or ocb2 -- ccm seems to be MUCH faster
    pbkdf2_iterations: 50, // number of key stretching iterations

    _badngramlist: [],
    _salt: null,
    _plaintext: null, // bitArray of file to be encrypted
    _cipherobj: null, // base64 encoded encrypted data in resultant object
    _passwords: [], // plaintext passwords
    _keys: [], // PBKDF2 strengthened passwords result
    _master: null, // the key that actually encrypts the plaintext
    _filename: null, // the unencrypted filename for use on retrieval
    _nPaswords: null, // number of passwords total
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
    makePassword: function(length, paranoia) {
        var pwd = [];
        var selections = this.randto(this._wordlist.length, length, paranoia);
        for(var i = 0; i < length; i++){
            pwd[i] = this._wordlist[selections[i]];
        }
        // Ensure no known bad combinations are displayed
        var joined = pwd.join(' ');
        for(i = 0; i < this._badngramlist.length; i++){
            if(joined.indexOf(this._badngramlist[i]) !== -1){
                return this.makePassword(length, paranoia);
            }
        }
        return joined;
    },

    // Generate array of num integers on [0, end)
    randto: function(end, num) {
        var maximum = Math.floor(2147483647 / end) * end; // regenerate if outside this
        var restrictRange = function(x){
            x = Math.abs(x);
            if(x >= maximum){ // the (even more) naive approach would skew distribution
                return restrictRange(sjcl.random.randomWords(num));
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
        this._salt = sjcl.random.randomWords(this.salt_length);
    },

    // Generate a key using PBKDF2 given a key (after salt has been generated)
    makeKeyFromPassword: function(password){
        return sjcl.misc.pbkdf2(password,
                                this._salt,
                                this.pbkdf2_iterations,
                                this.aes_key_strength * 32);
    },

    // Generate all possible password combinations needed given password list and number needed
    makeCombinedPasswords: function(passwords, nToUnlock){
        // store nPasswords and nToUnlock for later use
        this._nPasswords = passwords.length;
        this._nToUnlock = nToUnlock;
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
            passwords[i] = this.normalizeString(passwords[i]);
        }
        passwords.sort();
        combine(passwords, combined, null, nToUnlock, 0);
        return combined;
    },

    // Generate all key combinations (with progress callback)
    makeKeyCombinations: function(passwords, nToUnlock, callback){
        callback = callback || function(x){};
        this._keys = [];
        var combinations = this.makeCombinedPasswords(passwords, nToUnlock);
        // build a function chain using setTimeout so we don't TOTALLY lock up the browser
        var makeKeyBuilder = function(idx){
            if(idx < combinations.length){
                return function(){
                    setTimeout(function(){
                        keybearer._keys[idx] = keybearer.makeKeyFromPassword(combinations[idx]);
                        callback(keybearer._keys.length / combinations.length);
                    }, 50);
                    var next = makeKeyBuilder(idx + 1);
                    next();
                };
            } else {
                return function(){};
            }
        };
        callback(0);
        var keyBuilder = makeKeyBuilder(0);
        keyBuilder();
        return this._keys;
    },

    // Generate the encryption key
    makeAESKey: function(){
        this._master = sjcl.random.randomWords(this.aes_key_strength);
    },

    // Generate an object storing metadata
    makeMetadataObject: function(){
        return  { adata: '',
                  iter: this.pbkdf2_iterations,
                  mode: this.aes_cipher_mode,
                  cipher: 'aes',
                  ts: 128,
                  ks: this.aes_key_strength * 32,
                  salt: this._salt,
                  iv: sjcl.random.randomWords(4),
                  v: 1,
                  ct: null,
                  fn: this._filename,
                  nkeys: this._nPasswords,
                  nunlock: this._nToUnlock
                };
    },

    // Encrypt the plaintext
    encryptPlaintext: function(){
        var p = this.makeMetadataObject();
        this._lastMetadata = p;
        var prp = new sjcl.cipher[p.cipher](this._master);
        p.ct = sjcl.mode[p.mode].encrypt(
                                        prp,
                                        this._plaintext,
                                        p.iv,
                                        p.adata,
                                        p.ts);
        this._cipherobj = p;
        this.augmentWithEncryptedKeys(this._cipherobj);
    },

    // Add the master key, encrypted by every valid combination of passwords
    augmentWithEncryptedKeys: function(obj){
        var kivs = []; // IVs, one per key
        var encKeys = [];
        for(var i = 0; i < this._keys.length; i++){
            var iv = sjcl.random.randomWords(4);
            kivs.push(sjcl.codec.base64.fromBits(iv));
            var prp = new sjcl.cipher[obj.cipher](this._keys[i]);
            encKeys.push(sjcl.codec.base64.fromBits(sjcl.mode[obj.mode].encrypt(
                                                    prp,
                                                    this._master,
                                                    iv,
                                                    '',
                                                    obj.ts)));
        }
        obj.kivs = kivs;
        obj.keys = encKeys;
        // base64 encode output
        obj.salt = sjcl.codec.base64.fromBits(obj.salt);
        obj.iv = sjcl.codec.base64.fromBits(obj.iv);
        obj.ct = sjcl.codec.base64.fromBits(obj.ct);
    },

    // Turn metadata into relevant metadata + secret data
    changeToSecretData: function(obj){
        obj.pwds = this._passwords; // store the passwords
        // not truly happy about this double conversion
        obj.pt = sjcl.codec.base64.fromBits(this._plaintext);
        delete obj.salt;
        delete obj.iv;
        delete obj.ct;
    },

    // Set our binary file contents
    setPlaintext: function(data){
        this._plaintext = sjcl.codec.bytes.toBits(data);
    },

    // Set our unencrypted secret
    setFileName: function(fname){
        this._filename = fname;
    },

    // Reset generated keys
    resetKeys: function(){
        this._keys = [];
    },

    // checks if data has been loaded
    isPlaintextReady: function(){
        return(this._plaintext !== null);
    },

    // parses data into our encrypted object
    convertDataToJSON: function(data){
        this._cipherobj = JSON.parse(data);
    },

    // Get the cipherobject
    getCipherJSON: function(){
        return JSON.stringify(this._cipherobj);
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
