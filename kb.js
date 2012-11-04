keybearer = {
    // Public settings
    salt_length: 4, // in words (bytes * 4)
    aes_key_strength: 8, // 4 = 128 bits, 6 = 192, 8 = 256
    aes_cipher_mode: 'ocb2', // ccm or ocb2
    pbkdf2_iterations: 50, // number of key stretching iterations
    // Private variables
    _wordlist: [],
    _badngramlist: [],
    _salt: null,
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
    randto: function(end, num, paranoia) {
        var maximum = Math.floor(2147483647 / end) * end; // regenerate if outside this
        var restrictRange = function(x){
            x = Math.abs(x);
            if(x >= maximum){ // the (even more) naive approach would skew distribution
                return restrictRange(sjcl.random.randomWords(num, paranoia));
            }
            return x % end;
        };
        return sjcl.random.randomWords(num, paranoia).map(restrictRange);
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
    }

};

