keybearer = {
    // Private variables
    _wordlist: [],
    _badngramlist: [],
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
            if(x >= maximum){ // naive approach would skew distribution
                return restrictRange(sjcl.random.randomWords(num, paranoia));
            }
            return x % end;
        };
        return sjcl.random.randomWords(num, paranoia).map(restrictRange);
    }
};

