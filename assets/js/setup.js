(function () {
    document.addEventListener('DOMContentLoaded', function () {
        var el = document.getElementById('free2fa-qr');
        if (!el || typeof QRCode === 'undefined') return;
        var uri = el.getAttribute('data-uri');
        if (!uri) return;
        new QRCode(el, {
            text: uri,
            width: 200,
            height: 200,
            correctLevel: QRCode.CorrectLevel.M
        });
    });
})();
