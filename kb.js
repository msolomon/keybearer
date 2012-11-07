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
        var selections = this.randto(this._wordlist.length, length);
        for(var i = 0; i < length; i++){
            pwd[i] = this._wordlist[selections[i]];
        }
        // Ensure no known bad combinations are displayed
        var joined = pwd.join(' ');
        for(i = 0; i < this._badngramlist.length; i++){
            if(joined.indexOf(this._badngramlist[i]) !== -1){
                return this.makePassword(length);
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

    // Generate all key combinations
    makeKeyCombinations: function(passwords, nToUnlock){
        this._keys = [];
        var combinations = this.makeCombinedPasswords(passwords, nToUnlock);
        for(var i = 0; i < combinations.length; i++){
            keybearer._keys.push(keybearer.makeKeyFromPassword(combinations[i]));
        }
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
                  ft: this._filetype,
                  nkeys: this._nPasswords,
                  nunlock: this._nToUnlock
                };
    },

    // Decrypt the keys until the master is found
    decryptKeys: function(){
        var success = false;
        // currently, there should only be one key in this._keys
        // in the future, this may change, and it's an array anyway
        for(var i = 0; i < this._keys.length; i++){
            var prp = new sjcl.cipher[this._cipherobj.cipher](this._keys[i]);
            // do a linear search against every key that could hold the master key
            for(var j = 0; j < this._cipherobj.keys.length; j++){
                try {
                    var keyiv = this._cipherobj.keys[j];
                    this._master = sjcl.mode[this._cipherobj.mode].decrypt(prp,
                                                                           keyiv.key,
                                                                           keyiv.iv,
                                                                           this._cipherobj.adata,
                                                                           this._cipherobj.ts);
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
        var prp = new sjcl.cipher[this._cipherobj.cipher](this._master);
        this._plaintext = sjcl.mode[this._cipherobj.mode].decrypt(prp,
                                                                  this._cipherobj.ct,
                                                                  this._cipherobj.iv,
                                                                  this._cipherobj.adata,
                                                                  this._cipherobj.ts);
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
        var encKeys = [];
        for(var i = 0; i < this._keys.length; i++){
            var iv = sjcl.random.randomWords(4);
            var prp = new sjcl.cipher[obj.cipher](this._keys[i]);
            var key = sjcl.mode[obj.mode].encrypt(
                                                  prp,
                                                  this._master,
                                                  iv,
                                                  '',
                                                  obj.ts);
            encKeys.push({"iv": iv, "key": key});
        }
        obj.keys = encKeys;
        this.shuffle(obj.keys); // shuffle the keys
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
        obj.pwds = this._passwords; // store the passwords
        // not truly happy about this double conversion
        obj.pt = sjcl.codec.base64.fromBits(this._plaintext);
        delete obj.salt;
        delete obj.iv;
        delete obj.ct;
    },

    // Set our binary file contents
    setPlaintext: function(data){
        var view = new Uint8Array(data, 0, 100);
        this._plaintext = sjcl.codec.bitarrays.toBits(data);
    },

    // Set unencrypted filename
    setFileName: function(fname){
        this._filename = fname;
    },

    // Set unencrypted file MIME type
    setFileType: function(ftype){
        this._filetype = ftype;
    },

    // Get unencrypted filename
    getFileName: function(){
        return this._filename;
    },

    // Get unencrypted file MIME type
    getFileType: function(){
        return this._filetype;
    },

    // Get number of passwords possible
    getNPasswords: function(){
        return this._nPasswords;
    },

    // Get number of passwords possible for decryption
    getNPasswordsDecrypt: function(){
        return this._cipherobj.nkeys;
    },

    // Get number of passwords needed
    getNumToUnlock: function(){
        return this._nToUnlock;
    },

    // Reset generated keys
    resetKeys: function(){
        this._keys = [];
    },

    // checks if data has been loaded
    isPlaintextReady: function(){
        return(this._plaintext !== null);
    },

    // checks if encrypted data has been loaded
    isCipherObjectReady: function(){
        return(this._cipherobj !== null);
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
        this._salt = obj.salt;
        this._nPasswords = obj.nkeys;
        this._nToUnlock = obj.nunlock;
        this.setFileName(obj.fn); // set filename from JSON
        this.setFileType(obj.ft); // set filetype from JSON

        this._cipherobj = obj;
    },

    // Get the cipherobject
    getCipherJSON: function(){
        // copy the object -- this is fairly gross
        var obj = JSON.parse(JSON.stringify(this._cipherobj));
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
        return sjcl.codec.bitarrays.fromBits(this._plaintext);
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
