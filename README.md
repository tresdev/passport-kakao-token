# passport-kakao-token

This module provides to authenticate with an access token on connect middleware including express.js. It will be necessary to login on the Device.

It forked from [passport-kakao](https://github.com/rotoshine/passport-kakao) and refered from [passport-facebook-token](https://github.com/drudge/passport-facebook-token).

## How to Use

You can authenticate with calling REST API like below.



####  Sending access token as query parameter
```
GET /auth/kakao/token?access_token=[ACCESS_TOKEN]
```


####  Sending access token in HTTP body
```
POST /resource HTTP/1.1
Host: server.example.com

access_token=[ACCESS_TOKEN]
```


####  Sending access token as HTTP header
```
GET /auth/kakao/token
Authorization: Bearer [ACCESS_TOKEN]
```



And you should define a routing on your connect-style codes.
```
app.get('/auth/kakao/token', passport.authenticate('kakao-token'), function (req, res) {
    if (req.user) {
        // success
    } else {
        // fail
    }
});
```