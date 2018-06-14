var router = require('express').Router();
var mongoose = require('mongoose');
var BlueBird = require('bluebird');
var Cryptr = require('cryptr');


var jwt = require('jsonwebtoken');
var bcrypt = require('bcryptjs');
var config = require('../config');



mongoose.Promise = BlueBird;

mongoose.connect("mongodb://localhost:27017/jwt");

let genericSchema = new mongoose.Schema({
    any: {}
}, {
    strict: false,
    versionKey: false
});

let UserModel = mongoose.model('UserModel', genericSchema, 'users');

let Cipher = new Cryptr(config.secret);

router.post('/register', function (req, res) {

    var hashedPassword = bcrypt.hashSync(req.body.password, 8);

    var User = new UserModel({
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword
    });

    
    User.save(function (err, user) {
        if (err) return res.status(500).send("There was a problem registering the user.")
        // create a token
            var jwtPayload = Cipher.encrypt(JSON.stringify({
                id: user._id
            }));

            // console.log(jwtPayload);

            var token = jwt.sign({data:jwtPayload}, config.secret, {
                expiresIn: config.tokenExpiryTime // expires in 24 hours
            });
            res.status(200).send({
                auth: true,
                token: token
            });
        });
});

router.get('/check', verifyToken, function (req, res) {
    // console.log(123,req.userId);
    // var token = req.headers['x-authorization'];
    // if (!token) {return res.status(401).send({
    //     auth: false,
    //     message: 'No token provided.'
    // });

    // jwt.verify(token, config.secret, function (err, decoded) {
    //     let data = JSON.parse(Cipher.decrypt(decoded.data));
    //     console.log(decoded);
    //     console.log(1,data);
    //     if (err) return res.status(500).send({
    //         auth: false,
    //         message: 'Failed to authenticate token.'
    //     });

       UserModel.findById(req.userId, {
            password: 0
        }, function (err, user) {
            if (err) return res.status(500).send("There was a problem finding the user.");
            if (!user) return res.status(404).send("No user found.");

           res.status(200).send(user);
       });
    // });
});


router.post('/login', function (req, res) {
    UserModel.findOne({
        email: req.body.email
    }, function (err, user) {
        // console.log(user._doc.password);
        if (err) return res.status(500).send('Error on the server.');
        if (!user) return res.status(404).send('No user found.');
        var passwordIsValid = bcrypt.compareSync(req.body.password, user._doc.password);
        if (!passwordIsValid) return res.status(401).send({
            auth: false,
            token: null
        });
        var jwtPayload = Cipher.encrypt(JSON.stringify({
            id: user._id
        }));

        // console.log(jwtPayload);

        var token = jwt.sign({
            data: jwtPayload
        }, config.secret, {
            algorithm: 'HS512',
            expiresIn: config.tokenExpiryTime // expires in 24 hours
        });

        res.status(200).send({
            auth: true,
            token: token
        });
    });
});


function verifyToken(req, res, next) {
    var token = req.headers['x-authorization'];
    if (!token) {
        return res.status(403).send({
            auth: false,
            message: 'No token provided.'
        });
    }
    jwt.verify(token, config.secret, {
            algorithm: 'HS512'
        },function (err, decoded) {
            // console.log(decoded);
            
            if (err && !decoded) {
                console.log("not authenticated");                
                return res.status(500).send({
                    auth: false,
                    message: 'Failed to authenticate token.'
                });
            } else {
                console.log("authenticated");
                let data = JSON.parse(Cipher.decrypt(decoded.data));
                req.userId = data.id;
                next();
            }
        });

}

module.exports = router;