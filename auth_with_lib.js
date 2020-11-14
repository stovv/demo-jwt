const jwt = require('jsonwebtoken');
const bd = require("./test_bd.json");

function getFromBd(key){
    /* Replace this realisation to your own bg getting realization */
    return bd[key];
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
                    jwt: jwt.sign({ login: user.login, userId: user.id }, process.env.SECRET_KEY)
                }
            }
        }
        return null;
    },
    checkJWT: (token) =>{
        try{
            const decrypted = jwt.verify(token, process.env.SECRET_KEY);
            console.log("DECRYPTED", decrypted);
            return true;
        }catch{
            return false;
        }
    }
}