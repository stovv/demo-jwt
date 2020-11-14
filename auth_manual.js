const crypto = require('crypto');
const bd = require("./test_bd.json");

function getFromBd(key){
    /* Replace this realisation to your own bg getting realization */
    return bd[key];
}

function encodeBase64(data){
    return Buffer.from(JSON.stringify(data)).toString("base64")
}

function dencodeBase64(data){
    const json = Buffer.from(data, 'base64').toString();
    return JSON.parse(json);
}

function generateJWT(login, userId, header = { "alg": "HS256", "typ": "JWT"}){
    /*
    JWT token = header.payload.signature
    in header we can save hash type and some other data for create hash for signature

    in payload we save some user identification data. *Not password!
    payload hashed in base64 and this is not secure

    signature created with SECRET KEY on server, and cannot be decoded.
    it can only be compared with the new hashed signature
    ###################################################################################
    Algorithm:
        1. Hash header in base64
        2. Hash payload in base64
        3. Hash in HMAC-SHA256
           signature `${encrypted_header}.${encrypted_payload}` with secret key
        4. return hashed_header.hashed_payload.hashed_signature
    */
    payload = { login, userId };

    // header and payload = json encrypted in base64
    const header_base64 = encodeBase64(header);
    const payload_base_64 = encodeBase64(payload);

    // signature = encrypted in HMAC-SHA256 header_base64.payload_base64
    const unsignedToken = header_base64 + '.' + payload_base_64;
    const signature = crypto.createHmac('SHA256', process.env.SECRET_KEY)
        .update(unsignedToken)
        .digest('base64');
    return `${header_base64}.${payload_base_64}.${signature}`;
}


module.exports = {
    getUserAuth: (login, password) => {
        /*
        Algorithm:
            1. Find user in Base
            2. Check credentials
            3. return json with user_data and JWT token
         */
        const users = getFromBd('users');
        for (const user of users){
            // find user
            if (user.login === login){
                if (user.password !== password){
                    // check password
                    return {
                        logged: false,
                        error: "Invalid password"
                    }
                }
                return {
                    user: {
                        id: user.id,
                        name: user.name
                    },
                    jwt: generateJWT(user.login, user.id)
                }
            }
        }
        return null;
    },
    checkJWT: (jwt) =>{
        /*
        Algorithm:
            1. split token by '.', for separate header, payload and signature
            2. decrypt payload and header
            3. create new token from decrypted header and payload
            4. compare now generated token, and incoming token
         */
        try {
            const [ header_base_64, payload_base_64, _ ] = jwt.split('.');
            // You can add checking of hash algorithm type
            // Its not needed for example
            const header = dencodeBase64(header_base_64);

            const payload = dencodeBase64(payload_base_64);
            console.log("Decoded payload ->", payload);

            // generate new JWT from payload
            const newJWT = generateJWT(payload.login, payload.userId);
            console.log("NEW Token ->", newJWT);
            console.log("Incoming token ->", jwt);

            // return comparing new token incoming token
            return newJWT === jwt;
        }catch (error){
            console.log("Something wrong with checking JWT -> ", error);
        }
        return false;
    }
}