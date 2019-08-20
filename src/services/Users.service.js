// Library

const uaService = require('ua-parser-js');
// Internal Files

const log = require("./Logger.service");
const msg = require("../config/msg.config");
const CommonService = require("./Common.service");
const customMail = require('./Mailer.service').customMail;

const Users = require("../models/Users.model");
const UsersMeta = require('./../models/UsersMeta.model');


let retrieveUserById = async (_id) => {
    try {
        const user = await Users.findOne({
            _id
        }, {
            createdAt: 0,
            updatedAt: 0,
            password: 0,
            __v: 0
        }).exec();
        return CommonService.formatResponse(true, {
            data: user,
            message: msg["data-retrieved"]
        });
    } catch (error) {
        log('error', `${error}`)
        return CommonService.formatResponse(false, {
            message: msg["something-went-wrong"],
            error: error
        });
    }
};


let retrieveUserByEmail = async (email) => {
    try {
        const user = await Users.findOne({
            email
        }, {
            name: 1,
            email: 1,
            isActive: 1
        }).exec();
        return CommonService.formatResponse(true, {
            data: user,
            message: msg["data-retrieved"]
        });
    } catch (error) {
        log('error', `${error}`)
        return CommonService.formatResponse(false, {
            message: msg["something-went-wrong"],
            error: error
        });
    }
}

let retrieveUserSettings = async (_id) => {
    try {
        const settings = await UsersMeta.findOne({
            userId: _id
        }, {
            createdAt: 0,
            updatedAt: 0,
            __v: 0
        }).exec();
        return CommonService.formatResponse(true, {
            data: settings,
            message: msg["data-retrieved"]
        });
    } catch (error) {
        log('error', `${error}`)
        return CommonService.formatResponse(false, {
            message: msg["something-went-wrong"],
            error: error
        });
    }
}



module.exports.retrieveUserById = retrieveUserById;
module.exports.retrieveUserByEmail = retrieveUserByEmail;
module.exports.retrieveUserSettings = retrieveUserSettings;
