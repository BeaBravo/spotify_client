// PKCE authorization 

// will need a code verifier, which is a random string between 43 and 128 characters

const generateRandomString = (length) => {
    const possibleCharacters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    // console.log(possibleCharacters)
    const values = crypto.getRandomValues(new Uint8Array(length));
    return values.reduce((acc, x) => acc + possibleCharacters[x % possibleCharacters.length], "")
}

const codeVerifier = generateRandomString(64);

// need to hash the codeVerifier 
const sha256 = async (plain) => {
    const encoder = new TextEncoder();
    const data = encoder.encode(plain)
    return window.crypto.subtle.digest('SHA-256', data)
}