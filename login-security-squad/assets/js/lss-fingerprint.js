
document.addEventListener('DOMContentLoaded', function() {
    if ( ! sessionStorage.getItem( 'lss_fingerprint_sent' ) ) {
        // Generate a device fingerprint.
        var fingerprint = [
            navigator.userAgent,
            screen.width,
            screen.height,
            new Date().getTimezoneOffset()
        ].join(',');

        // Send the fingerprint to the server.
        var xhr = new XMLHttpRequest();
        xhr.open('POST', lss_fingerprint_ajax.ajax_url);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        xhr.onload = function() {
            if (xhr.status === 200) {
                console.log('Fingerprint sent.');
                sessionStorage.setItem( 'lss_fingerprint_sent', 'true' );
            }
        };
        xhr.send('action=lss_update_fingerprint&fingerprint=' + btoa(fingerprint) + '&nonce=' + lss_fingerprint_ajax.nonce);
    }
});
