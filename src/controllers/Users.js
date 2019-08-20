const router = require('express').Router();
const uaParser = require('ua-parser-js');
const useragent = require('useragent');
const iplocation = require("iplocation").default;
const requestIp = require('request-ip');

const publicIp = require('public-ip');

// Internal Files
const log = require("./../services/Logger.service");
const UsersService = require('./../services/Users.service');


router.get('/parse', async (req, res) => {
    // let ip = await iplocation('183.83.224.157', []);
    const clientIp = requestIp.getClientIp(req);
    let ip = await publicIp.v4()
    return res.json(ip)
    // var ua = uaParser(req.headers['user-agent']);
    // return res.json(ua);
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
