// const auth = require("./auth_with_lib");
// You can replace this import to with_lib to check how it works
const auth = require("./auth_manual");
const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
// use .env file in process
require('dotenv').config({ path: './.env' });


const app = express();
//parse cookie headers to req.cookies
app.use(cookieParser());
// parse body of req
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

// ------- routes ---------
app.get('/', (req, res) => {
    res.sendFile( `${__dirname}/frontend/index.html`);
});

app.get('/style.css', (req, res) => {
    res.sendFile(`${__dirname}/frontend/style.css`);
});

app.get('/private-page', (req, res) => {
    //check exists JWT token in cookies
    if (req.cookies.auth && auth.checkJWT(req.cookies.auth)){
        res.sendFile(`${__dirname}/frontend/private.html`);
        return;
    }
    // Redirect because user not logged
    res.redirect("/");
});

// -------  api ---------
app.post('/auth', (req, res) => {
    const auth_data = auth.getUserAuth(req.body.login, req.body.password);

    if (auth_data !== null){
        res.status(200).send({
            logged: true,
            ...auth_data
        });
        return;
    }

    res.status(403).send({
        logged: false,
        message: "User credentials is invalid!"
    })

});

app.post('/private-request', (req, res) => {
    // check valid JWT token in headers
    if (req.headers.authorization &&
        auth.checkJWT(req.headers.authorization.replace('Bearer ', '')))
    {
        res.status(200).send({
            message: "You can check this request!"
        })
        return;
    }
    // Redirect because user not logged
    res.status(403).send({
        message: "You can't check this request :c, please provide valid token"
    });
});

app.listen(process.env.PORT, () => {
    console.log(`Server listen by http://localhost:${process.env.PORT}.\nctrl-c for stop server`)
});