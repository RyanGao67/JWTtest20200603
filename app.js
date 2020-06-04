const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const {verify} = require('jsonwebtoken');
const {hash, compare} = require('bcryptjs');
require('dotenv/config'); // to use the .env file information => eg, process.env.PORT


const {fakeDB} = require('./fakeDB.js');
const {createAccessToken, createRefreshToken, sendAccessToken, sendRefreshToken} = require('./tokens.js');
const {isAuth} = require('./isAuth.js');
// 1. register a user
// 2. login a user
// 3. logout a user
// 4. setup a protected route
// 5. get a new access token with a refresh token

const server = express();

// middleware for cookie handling
server.use(cookieParser());

server.use(
    cors(
        {
            origin:'http://localhost:3000', // frontend react app
            credentials:true                // frontend and server can communicate
        }
    )
);

// Needed to be able to read body data
server.use(express.json());// to support json encoded bodies
server.use(express.urlencoded({extended:true})); // support url encoded bodies


server.post('/register', async (req, res) => {
    const {email, password} = req.body;
    try{
        // check if the user exists
        const user = fakeDB.find(user => user.email === email);
        if(user)throw new Error('User already exists');
        const hashedPassword = await hash(password, 10);
        // if not exists, put the user into the DB
        fakeDB.push({id:fakeDB.length, email:email, password:hashedPassword});
        res.send({message:'User Created'});
        console.log('this is the information after register a user');  console.log(fakeDB);
    }catch (err){
        res.send({error:`${err.message}`});
    }
});

server.post('/login', async (req, res)=>{
    const {email, password} = req.body;
    try{
        const user = fakeDB.find(user => user.email===email);
        if(!user)throw new Error("User does not exist");
        const valid = await compare(password, user.password);
        console.log('this is the password');console.log(password);
        console.log('this is the user password');console.log(user.password);
        if(!valid)throw new Error("Password not correct");
        // access token should have a short life time and refresh token longer life time
        const accesstoken = createAccessToken(user.id);
        const refreshtoken = createRefreshToken(user.id);
        user.refreshtoken = refreshtoken;
        console.log(fakeDB);
        // send token refreshtoken as a cookie and access token as response
        sendRefreshToken(res, refreshtoken);
        sendAccessToken(res, req, accesstoken);
    }catch(err){
        res.send({error:`${err.message}`});
    }
});

server.post('/logout', (req, res)=>{
    res.clearCookie('refreshtoken', {path:'/refresh_token'});
    return res.send({
        message:'Logged out',
    });
});

server.get('/protected', async (req, res)=>{
    try{
        const userId = isAuth(req);
        if(userId!=null){
            res.send({
                data:'This is protected data.'
            });
        }
    }catch(err){
        res.send(err.message);
    }
});

server.post('/refresh_token', (req, res)=>{
    const token = req.cookies.refreshtoken;
    if(!token)return res.send({accesstoken:''});
    let payload = null;
    try{
        payload = verify(token, process.env.REFRESH_TOKEN_SECRET);
    }catch(err){
        return res.send({accesstoken:''});
    }
    const user = fakeDB.find(user=>user.id === payload.userId);
    if(!user)return res.send({accesstoken:''});
    if(user.refreshtoken!==token){
        return res.send({accesstoken:''});
    }
    const accesstoken = createAccessToken(user.id);
    const refreshtoken = createRefreshToken(user.id);
    user.refreshtoken = refreshtoken;
    sendRefreshToken(res, refreshtoken);
    return res.send({accesstoken});
});

server.listen(process.env.PORT, ()=>{
    console.log(`Server listening on port ${process.env.PORT}`);
});

