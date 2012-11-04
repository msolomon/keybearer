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
      $('#genkeys').click(kbp.generateKeys);
    },

    // Event handler for changing number of friends
    generateAllFriendPass: function() {
        var gk = $('#generated_pass');
        gk.empty();
        var n_keys = $('#num_pass option:selected').val();
        var reset = function(ev) {
           $('#' + ev.currentTarget.id.replace('reset_', '')).
            val(keybearer.makePassword($('#pass_len').val()));
        };
        for(var i = 0; i < n_keys; i++){
            gk.append(kbp.mkFriendPass(i, keybearer.makePassword($('#pass_len').val())));
            $('#reset_pass' + i).click(reset);
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

    // Generate keys
    generateKeys: function(){
        var passwords = kbp.getAllPass();
        passwords = keybearer.makeCombinedPasswords(passwords, kbp.getNumUnlock());
        for(var i = 0; i < passwords.length; i++){
            var p = keybearer.makeKeyFromPassword(passwords[i]);
            $('#generatedkeys').append(document.createTextNode(passwords[i]));
            $('#generatedkeys').append('<br>');
            $('#generatedkeys').append(document.createTextNode(sjcl.codec.base64.fromBits(p)));
            $('#generatedkeys').append('<br>');
        }
    },

    updateKeygenCount: function(){
        $('#nkeys_to_gen').text(kbp.nChooseK(kbp.getNumPass(), kbp.getNumUnlock()));
    },

    // Friend form template
    ffTemplate: [
        '<div class="pass">',
        '<button id="reset_passX">Regenerate</button>',
        '<input type="text" class="password" id="passX" value="PASSWORD" />',
        '</div>'
        ].join('\n'),

    // Fill in form template
    mkFriendPass: function(friendID, password){
        return kbp.ffTemplate.replace(/passX/g, 'pass' + friendID).
            replace('PASSWORD', password);
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
    }
};
