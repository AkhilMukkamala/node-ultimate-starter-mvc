const router = require('express').Router();
const publicIp = require('public-ip');
const geoip = require('geoip-lite');


// Internal Files
const log = require("./../services/Logger.service");
const UsersService = require('./../services/Users.service');




router.get('/parse', async (req, res) => {
    return res.status(200).json({
        ip: req.clientIp,
        clientAddress: req.clientAddress,
        ua: req.useragent
    })

});

router.get('/user', async (req, res) => {
    let { _id } = req.query;
    let result = await UsersService.retrieveUserById(_id);
    return res.json(result);
});

router.get('/settings', async (req, res) => {
    let { _id } = req.query;
    let result = await UsersService.retrieveUserSettings(_id);
    return res.json(result);
});


router.get('/users', async (req, res) => {
    // check whether he has admin permission to retrieve all the users.
});


// Based on the permissions allow user to create e

module.exports = router;
