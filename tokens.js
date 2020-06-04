const {sign} = require('jsonwebtoken');
const createAccessToken = userId=>{
    console.log('this is the access secret from env');console.log(process.env.ACCESS_TOKEN_SECRET);
    return sign({userId:userId}, process.env.ACCESS_TOKEN_SECRET,{
        expiresIn:'15m',
    })
};
const createRefreshToken = userId => {
    return sign({userId:userId}, process.env.REFRESH_TOKEN_SECRET, {
        expiresIn:'7d',
    })
};
const sendAccessToken = (res, req, accesstoken)=>{
    res.send({
        accesstoken, email:req.body.email,
    });
}
const sendRefreshToken = (res, token) =>{
    res.cookie(
        'refreshtoken', 
        token, 
        {
            httpOnly:true,               // we can not access the cookies from the client so we cant modify the cookie with javascript
            path:'/refresh_token'        // because dont want to send this cookie with every request
        }
    );
}
module.exports = {createAccessToken,createRefreshToken,sendAccessToken,sendRefreshToken}