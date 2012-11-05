kbp = {
    // tracks ready state
    _ready_wordlist: false,
    _ready_entropy: false,
    _ready_ngram: false,

    // Prepare keybearer
    init: function(wordlistURL, badngramlistURL) {
        sjcl.random.setDefaultParanoia(10);
        sjcl.random.addEventListener('progress', function(){
            $('#entropy_frac').text(sjcl.random.getProgress());
        });
        var ent_ready = function(){
            $('#entropy_msg').remove();
            $('#entropy_frac').remove();
            // generate salt
            keybearer.makeSalt();
            kbp._ready_entropy = true;
            kbp.try_start();
        };
        sjcl.random.addEventListener('seeded', ent_ready);

        sjcl.random.startCollectors();
        // if we already have enough entropy, then we're good
        if(sjcl.random.isReady()){
            ent_ready();
        }
        keybearer.loadWordlist(wordlistURL, '_wordlist', function(){
            kbp._ready_wordlist = true;
            kbp.try_start();
        });
        keybearer.loadWordlist(badngramlistURL, '_badngramlist', function(){
            kbp._ready_ngram = true;
            kbp.try_start();
        });
    },

    // make sure everything is loaded and seeded before continuing
    try_start: function(){
        if(kbp._ready_wordlist && kbp._ready_entropy && kbp._ready_ngram){
            kbp.bind_input();
        }
    },

    // Bind input change events
    bind_input: function() {
      $('#num_pass').change(kbp.generateAllFriendPass);
      $('#num_pass').change(kbp.checkUnlockPass);
      $('#num_pass').change(kbp.updateKeygenCount);
      $('#num_unlock_pass').change(kbp.updateKeygenCount);
      $('#pass_len').change(kbp.generateAllFriendPass);
      $('#num_pass').change();
      $('#encrypt').click(kbp.encrypt);
      $('#decrypt').click(kbp.decrypt);
      $('#secretfile').change(kbp.choosePlaintextFile);
      $('#decfile').change(kbp.chooseEncryptedFile);
    },

    // Event handler for changing number of friends
    generateAllFriendPass: function() {
        var gk = $('#generated_pass');
        gk.empty();
        var n_keys = $('#num_pass option:selected').val();
        var reset = function(ev) {
           $('#' + ev.currentTarget.id.replace('reset_', '')).
            val(keybearer.makePassword($('#pass_len').val()));
            keybearer.resetKeys();
        };
        for(var i = 0; i < n_keys; i++){
            gk.append(kbp.mkFriendPass(i, keybearer.makePassword($('#pass_len').val())));
            $('#reset_pass' + i).click(reset);
      }
    },

    // Generate n areas for decryption entry (really only need m)
    generateAllDecPass: function(n, m) {
        var da = $('#decpass_area');
        da.empty();
        da.append(["<p>Enter up to",
                   n,
                   "passcodes, including spaces. Only",
                   m,
                   "passcodes are necessary."].join(' '));
        da.append('<ol id="declist"></ol>');
        var l = $('#declist');
        for(var i = 0; i < n; i++){
            l.append(kbp.mkDecPass(i));
        }
    },

    // Ensure more friends aren't needed to unlock than exist
    checkUnlockPass: function (){
        var max_sel = kbp.getNumPass();
        var sel = Math.min(max_sel,
                           $('#num_unlock_pass option:selected').val());
        // always rebuild the list. simple special cases could avoid this
        var nuk = $('#num_unlock_pass');
        nuk.empty();
        for(var i = 1; i <= max_sel; i++){
            nuk.append('<option value=I>I</option>'.
                    replace('=I', '=I' + (i == sel ? ' selected' : '')).
                    replace(/I/g, i));
        }
    },

    getNumPass: function(){
       return $('#num_pass option:selected').val();
    },

    getNumUnlock: function(){
       return $('#num_unlock_pass option:selected').val();
    },

    getAllPass: function(){
        var npass = kbp.getNumPass();
        var passwords = [];
        for(var i = 0; i < npass; i++){
            passwords[i] = $('#pass' + i).val();
        }
        return passwords;
    },

    // shuffle an array in-place using Fisher-Yates
    fisherYates: function(arr) {
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

    // Get all entered passwords, and return M that have been filled out
    getMDecPass: function(n, m){
        var passwords = [];
        for(var i = 0; i < n; i++){
            var s = keybearer.normalizeString($('#decpass' + i).val());
            if(s.length > 0) // omit empty passwords
                passwords.push(s);
        }
        if(passwords.length < m)
            alert("You must enter at least " + m + " passcodes to decrypt this message.");
        kbp.fisherYates(passwords); // shuffle the order
        passwords = passwords.slice(0, m);
        passwords.sort();
        return passwords;
    },

    // Generate keys and encrypt
    encrypt: function(){
        if(!keybearer.isPlaintextReady()){
            alert("You must load a file before before encrypting it!");
            return;
        }
        var passwords = kbp.getAllPass();
        var encrypt_pt = function(){
            keybearer.makeAESKey();
            keybearer.encryptPlaintext();
        };
        keybearer.makeKeyCombinations(passwords, kbp.getNumUnlock(), function(pcnt){
            $('#keygenprogress').text(kbp.toPercent(pcnt));
            if(pcnt === 1){
                encrypt_pt();
                $('#encryptionprogress').text(kbp.toPercent(1));
                var blob = new Blob([keybearer.getCipherJSON()], {type: 'application/json'});
                var link = document.createElement('a');
                window.URL = window.URL || window.webkitURL;
                link.href = window.URL.createObjectURL(blob);
                link.download = keybearer.getFileName() + '.keybearer.json';
                link.innerHTML = 'Download encrypted JSON';
                $('#encdownloadlink').empty().append(link);
            }
        });
    },

    updateKeygenCount: function(){
        $('#nkeys_to_gen').text(kbp.nChooseK(kbp.getNumPass(), kbp.getNumUnlock()));
    },

    // Friend form template
    ffTemplate: [
        '<div class="pass">',
        '<div id="reset_passX" class="btn">Regenerate</div>',
        '<input type="text" class="password" id="passX" value="PASSWORD" />',
        '</div>'
        ].join('\n'),

    // Decryption entry template
    decTemplate: [
        '<li class="decpass">',
        '<input type="text" class="decpassinput" id="decpassX" value="" />',
        '</li>'
        ].join('\n'),

    // Fill in form template
    mkFriendPass: function(friendID, password){
        return kbp.ffTemplate.
            replace(/passX/g, 'pass' + friendID).
            replace('PASSWORD', password);
    },

    // Fill in decryption entry template
    mkDecPass: function(friendID){
        return kbp.decTemplate.
            replace(/decpassX/g, 'decpass' + friendID);
    },

    // n choose k (to show # keys generated)
    nChooseK: function(n, k){
        var factorial = function(num){
            var out = 1;
            for(var i = 2; i <= num; i++)
                out *= i;
            return out;
        };

        return factorial(n) / (factorial(k) * factorial(n - k));
    },

    // "upload" (read) a plaintext file in JS using HTML5 features
    choosePlaintextFile:  function(evt){
        $('#secretfilename').text($('#secretfile').val());
        var file = evt.target.files[0];
        if(!file) return; // no file selected
        var reader = new FileReader();
        // event handler for when secret file is loaded
        reader.onload = function(evt){
            keybearer.setPlaintext(evt.target.result);
            keybearer.setFileName(file.name);
            keybearer.setFileType(file.type); // store MIME time
        };
        reader.onprogress = function(evt){
            $('#secretfileprogress').text(kbp.toPercent(evt.loaded/evt.total));
        };
        reader.readAsArrayBuffer(file);
    },

    // "upload" (read) an encrypted file in JS using HTML5 features
    chooseEncryptedFile:  function(evt){
        $('#decfilename').text($('#decfile').val());
        var file = evt.target.files[0];
        if(!file) return; // no file selected
        var reader = new FileReader();
        // event handler for when secret file is loaded
        reader.onload = function(evt){
            try {
                keybearer.setCipherJSON(evt.target.result);
                $('#decfileprogress').text('Success!');
                var n = keybearer.getNPasswords();
                var m = keybearer.getNumToUnlock();
                kbp.generateAllDecPass(n, m);
            } catch(err) {
                alert("Error loading keybearer file:\n" + err);
                $('#decfileprogress').text('Error');
            }
        };
        reader.onprogress = function(evt){
            $('#decfileprogress').text(kbp.toPercent(evt.loaded/evt.total));
        };
        reader.readAsBinaryString(file);
    },

    // Begin the decryption process
    decrypt: function(){
        if(!keybearer.isCipherObjectReady()){
            alert("You must load a file before before decrypting it!");
            return;
        }
        var decrypt = function(){
            var gotKey = keybearer.decryptKeys();
            if(!gotKey){
                alert('Could not decode key. Check your passcodes');
                return;
            }
            keybearer.decryptCiphertext();
            $('#decryptionprogress').text(kbp.toPercent(1));
            var blob = new Blob([keybearer.getPlaintext()],
                                {type: keybearer.getFileType()});
            var link = document.createElement('a');
            window.URL = window.URL || window.webkitURL;
            link.href = window.URL.createObjectURL(blob);
            link.download = keybearer.getFileName();
            link.innerHTML = 'Download decrypted ' + link.download;
            $('#decdownloadlink').empty().append(link);
        };
        try {
            var n = keybearer.getNPasswords();
            var m = keybearer.getNumToUnlock();
            var passwords = kbp.getMDecPass(n, m);
            keybearer.makeKeyCombinations(passwords, m, function(frac){
                $('#keycheckprogress').text(kbp.toPercent(frac));
                if(frac === 1){ // done making decryption key (there is only one)
                    decrypt();
                }
            });
        } catch(err){
            alert("Error decrypting keybearer file:\n" + err);
             throw err;
        }
    },

    toPercent: function(fraction){
        return Math.round(fraction * 100) + '%';
    }

};
