kbp = {
    // Prepare keybearer
    init: function(wordlistURL, badngramlistURL) {
        keybearer.loadWordlist(wordlistURL, '_wordlist', kbp.bind_input);
        keybearer.loadWordlist(badngramlistURL, '_badngramlist', kbp.bind_input);
    },

    // Bind input change events
    bind_input: function() {
      kbp.bindNumFriendsChange();
    },

    // Event handler for changing number of friends
    bindNumFriendsChange: function() {
        $('#num_keys').change(function(ev) {
            var gk = $('#generated_keys');
            gk.empty();
            var n_keys = parseInt($('#num_keys option:selected').text());
            for(var i = 0; i < n_keys; i++){
              gk.append(kbp.mkFriendKey(i, keybearer.makePassword(6)));
              $('#reset_key' + i).click(function(ev) {
                $('#' + ev.currentTarget.id.replace('reset_', '')).
                  val(keybearer.makePassword(6));
              });
            }
        });
        $('#num_keys').change();
    },

    // Friend form template
    ffTemplate: '\
      <div class="key"> \
        <button id="reset_keyX">Regenerate</button> \
        <input type="text" class="password" id="keyX" value="PASSWORD" /> \
      </div>',

    // Fill in form template
    mkFriendKey: function(friendID, password){
        return kbp.ffTemplate.replace(/keyX/g, 'key' + friendID).
            replace('PASSWORD', password);
    }
}
