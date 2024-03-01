// Variables 
const clientId = '4ed2fc5a69a94fa9a6decf83ee32e5d0' //from my app
const redirectURL = 'https://localhost:3000'

const authorizationEndpoint = "https://accounts.spotify.com/authorize";
const tokenEndpoint = "https://accounts.spotify.com/api/token";
const scope = 'user-read-private user-read-email';


// PKCE authorization 
async function redirectToSpotifyAuthorize() {


    // will need a code verifier, which is a random string between 43 and 128 characters
    const generateRandomString = (length) => {
        const possibleCharacters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        // console.log(possibleCharacters)
        const values = crypto.getRandomValues(new Uint8Array(length));
        return values.reduce((acc, x) => acc + possibleCharacters[x % possibleCharacters.length], "")
    }

    const codeVerifier = generateRandomString(64);
    window.localStorage.setItem('codeVerifier', codeVerifier)

    // need to hash the codeVerifier 
    const sha256 = async (plain) => {
        const encoder = new TextEncoder();
        const data = encoder.encode(plain)
        return window.crypto.subtle.digest('SHA-256', data)
    }

    // base64encode return the base64 representation of the digest 
    const base64encode = (input) => {
        return btoa(String.fromCharCode(...new Uint8Array(input)))
            .replace(/=/g, '')
            .replace(/\+/g, '-')
            .replace(/\//g, '_');
    }

    // putting it all together 
    const hashed = await sha256(codeVerifier);
    const codeChallenge = base64encode(hashed);
}