function createRandomString() {
    const charset = '0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz-_~.';
    let random = '';
    const randomValues = Array.from(crypto.getRandomValues(new Uint8Array(43)));
    randomValues.forEach(v => (random += charset[v % charset.length]));
    return random;
}

function urlEncodeBase64(input) {
    const b64Chars = { '+': '-', '/': '_', '=': '' };
    return input.replace(/[\+\/=]/g, (m) => b64Chars[m]);
}

function sha256(input) {
    return window.crypto.subtle.digest({ name: 'SHA-256' }, new TextEncoder().encode(input));
}

function bufferToBase64URLEncoded(input) {
    const ie11SafeInput = new Uint8Array(input);
    return urlEncodeBase64(
        window.btoa(String.fromCharCode(...Array.from(ie11SafeInput)))
    );
}

  function getQueryParams() {
    const {search} = window.location;
    return search.replace('?', '').split('&').map(queryParam => {
      const keyValue = queryParam.split('=');
      return {
        key: keyValue[0],
        value: keyValue[1]
      }
    });
  }