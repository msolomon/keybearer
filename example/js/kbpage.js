kbp = {
    // tracks ready state
    _ready_wordlist: false,
    _ready_entropy: false,
    _ready_ngram: false,

    // Prepare keybearer
    init: function(wordlistURL, badngramlistURL) {
        try {
            new Blob();
        } catch(err){
            $('#error').append(['<div class="alert alert-error">',
                                    '<h3>This browser does not support the FileAPI,',
                                    'which is required.',
                                    'Consider trying again with the latest Firefox or Chrome.',
                                    '</h3></div>'].join('\n'));
        }
        sjcl.random.setDefaultParanoia(10);
        sjcl.random.addEventListener('progress', function(pct){
            $('#entropy_frac').text(kbp.toPercent(pct));
            $('#entropy_progressbar').width(pct * 100 + "%");
        });
        var ent_ready = function(){
            $('#entropy_msg').remove();
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
      $('#num_pass > .btn').click(kbp.generateAllFriendPass);
      $('#num_pass > .btn').click(kbp.checkUnlockPass);
      $('#num_pass > .btn').click(kbp.updateKeygenCount);
      $('#num_unlock_pass > .btn').click(kbp.updateKeygenCount);
      $('#pass_len > .btn').click(kbp.generateAllFriendPass);
      $('#encrypt').click(kbp.encrypt);
      $('#decrypt').click(kbp.decrypt);
      $('#secretfile').change(kbp.choosePlaintextFile);
      $('#decfile').change(kbp.chooseEncryptedFile);
      $('#num_pass > .active').click();
      $('#copypass').click(kbp.copyPasswords);
    },

    // Event handler for changing number of friends
    generateAllFriendPass: function(evt) {
        var gk = $('#generated_pass');
        gk.empty();
        var n_keys, p_len;
        if(evt.target.id.match(/l/)){ // length event generated change
            p_len = evt.target.value;
            n_keys = kbp.getNumPass();
        } else {
            n_keys = evt.target.value;
            p_len = $('#pass_len > .active').val();
        }
        var reset = function(ev) {
            var s = '#' + ev.currentTarget.id.replace('reset_', '');
            $(s).val(keybearer.makePassword(p_len));
            keybearer.resetKeys();
        };
        for(var i = 0; i < n_keys; i++){
            gk.append(kbp.mkFriendPass(i, keybearer.makePassword(p_len)));
            $('#reset_pass' + i).click(reset);
      }
    },

    // Generate n areas for decryption entry (really only need m)
    generateAllDecPass: function(n, m) {
        var da = $('#decpass_area');
        da.empty();
        da.append(['<div class="alert alert-info">',
                   'Enter up to',
                   n,
                   'passcodes, including spaces. Only',
                   m,
                   'passcodes are necessary.',
                   '</div>'].join(' '));
        for(var i = 0; i < n; i++){
            da.append(kbp.mkDecPass(i));
        }
    },

    // Ensure more friends aren't needed to unlock than exist
    checkUnlockPass: function (evt){
        var max_sel = evt.target.value;
        var sel = Math.min(max_sel, kbp.getNumUnlock());
        // always rebuild the list. simple special cases could avoid this
        var nuk = $('#num_unlock_pass');
        nuk.empty();
        for(var i = 1; i <= max_sel; i++){
            nuk.append('<button id="mI" class="btn" value=I>I</button>'.
                    replace('btn', 'btn' + (i == sel ? ' active' : '')).
                    replace(/I/g, i));
        }
        $('#num_unlock_pass > .btn').click(kbp.updateKeygenCount);
    },

    getNumPass: function(){
       return $('#num_pass > .active').val();
    },

    getNumUnlock: function(){
       return $('#num_unlock_pass > .active').val();
    },

    getAllPass: function(){
        var npass = kbp.getNumPass();
        var passwords = [];
        for(var i = 0; i < npass; i++){
            passwords[i] = $('#pass' + i).val();
        }
        return passwords;
    },

    // Get all entered passwords, and return M that have been filled out
    getMDecPass: function(n, m){
        var passwords = [];
        for(var i = 0; i < n; i++){
            $('#label' + i).attr('class', 'add-on');
            var s = keybearer.normalizeString($('#decpass' + i).val());
            if(s.length > 0) // omit empty passwords
                passwords.push(s);
        }
        if(passwords.length < m){
            alert("You must enter at least " + m + " passcodes to decrypt this message.");
            return passwords;
        }
        keybearer.shuffle(passwords); // shuffle the order
        passwords = passwords.slice(0, m);
        passwords.sort();
        // highlight the winning keys. this should really be in a different function
        for(i = 0; i < n; i++){
            var str = keybearer.normalizeString($('#decpass' + i).val());
            for(var j = 0; j < m; j++){
                if(str == passwords[j]){
                    $('#label' + i).addClass('btn-info');
                }
            }
        }
        return passwords;
    },

    // Generate keys and encrypt
    encrypt: function(){
        if(!keybearer.isPlaintextReady()){
            alert("You must load a file before before encrypting it!");
            return;
        }
        var passwords = kbp.getAllPass();
        keybearer.makeKeyCombinations(passwords, kbp.getNumUnlock());
        keybearer.makeAESKey();
        keybearer.encryptPlaintext();
        var blob = new Blob([keybearer.getCipherJSON()], {type: 'application/json'});
        var link = document.createElement('a');
        window.URL = window.URL || window.webkitURL;
        link.href = window.URL.createObjectURL(blob);
        link.download = keybearer.getFileName() + '.kbr.json';
        link.innerHTML = 'Download encrypted' + link.download;
        window.URL.revokeObjectURL($('#encdownloadlink > a').attr('href'));
        $('#encdownloadlink').empty().append(link);
    },

    updateKeygenCount: function(evt){
        var n, m;
        if(evt.target.id.match(/n/)){ // numpass changed
            n = evt.target.value;
            m = kbp.getNumUnlock();
        } else {
            n = kbp.getNumPass();
            m = evt.target.value;
        }
        $('#nkeys_to_gen').text(kbp.nChooseK(n, m));
    },

    // Friend form template
    ffTemplate: [
        '<form class="pass form-inline input-prepend input-append">',
        '<input id="reset_passX" class="btn" type="button" value="Regenerate"></input>',
        '<input type="text" class="password regen" id="passX" value="PASSWORD" />',
        '<span class="add-on">X+1</span>',
        '</form>'
        ].join('\n'),

    // Decryption entry template
    decTemplate: [
        '<form class="decpass pass form-inline input-prepend">',
        '<span id="labelX" class="add-on">X+1</span>',
        '<input type="text" class="decpassinput decpassin" id="decpassX" value="" />',
        '</form>'
        ].join('\n'),

    // Fill in form template
    mkFriendPass: function(friendID, password){
        return kbp.ffTemplate.
            replace(/X\+1/g, friendID + 1).
            replace(/X/g, friendID).
            replace('PASSWORD', password);
    },

    // Fill in decryption entry template
    mkDecPass: function(friendID){
        return kbp.decTemplate.
            replace(/X\+1/g, friendID + 1).
            replace(/X/g, friendID);
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
        $('#secretfilename').text($('#secretfile').val() || 'No file selected');
        var file = evt.target.files[0];
        if(!file) return; // no file selected
        var reader = new FileReader();
        // event handler for when secret file is loaded
        reader.onload = function(evt){
            keybearer.setPlaintext(evt.target.result);
            keybearer.setFileName(file.name);
            keybearer.setFileType(file.type); // store MIME time
        };
        reader.readAsArrayBuffer(file);
    },

    // "upload" (read) an encrypted file in JS using HTML5 features
    chooseEncryptedFile:  function(evt){
        $('#decfilename').text($('#decfile').val() || 'No file selected');
        var file = evt.target.files[0];
        if(!file) return; // no file selected
        var reader = new FileReader();
        // event handler for when secret file is loaded
        reader.onload = function(evt){
            try {
                keybearer.setCipherJSON(evt.target.result);
                var n = keybearer.getNPasswords();
                var m = keybearer.getNumToUnlock();
                kbp.generateAllDecPass(n, m);
            } catch(err) {
                alert("Error loading keybearer file:\n" + err);
                $('#decfileprogress').text('Error');
            }
        };
        reader.readAsBinaryString(file);
    },

    // Begin the decryption process
    decrypt: function(){
        if(!keybearer.isCipherObjectReady()){
            alert("You must load a file before before decrypting it!");
            return;
        }
        try {
            var n = keybearer.getNPasswordsDecrypt();
            var m = keybearer.getNumToUnlock();
            var passwords = kbp.getMDecPass(n, m);
            keybearer.makeKeyCombinations(passwords, m);
            var gotKey = keybearer.decryptKeys();
            if(!gotKey){
                alert('Could not decode key, check the passcodes');
                return;
            }
            keybearer.decryptCiphertext();
            var blob = new Blob([keybearer.getPlaintext()],
                                {type: keybearer.getFileType()});
            var link = document.createElement('a');
            window.URL = window.URL || window.webkitURL;
            link.href = window.URL.createObjectURL(blob);
            link.download = keybearer.getFileName();
            link.innerHTML = 'Download decrypted ' + link.download;
            window.URL.revokeObjectURL($('#decdownloadlink > a').attr('href'));
            $('#decdownloadlink').empty().append(link);
        } catch(err){
            alert("Error decrypting keybearer file:\n" + err);
             throw err;
        }
    },

    toPercent: function(fraction){
        return Math.round(fraction * 100) + '%';
    },

    copyPasswords: function(){
        var passwords = kbp.getAllPass();
        for(var i = 0; i < passwords.length; i++){
            passwords[i] = keybearer.normalizeString(passwords[i]);
        }
        $('#modalbody').html(passwords.join('<br>'));
        // highlight after animation completes
        setTimeout(function(){kbp.selectText('modalbody');}, 500);
    },

    selectText: function(element) {
        var doc = document;
        var text = doc.getElementById(element);
        var range, selection;
        if (doc.body.createTextRange) { //ms
            range = doc.body.createTextRange();
            range.moveToElementText(text);
            range.select();
        } else if (window.getSelection) { //all others
            selection = window.getSelection();
            range = doc.createRange();
            range.selectNodeContents(text);
            selection.removeAllRanges();
            selection.addRange(range);
        }
    }

};
