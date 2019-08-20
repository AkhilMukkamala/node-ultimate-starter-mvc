let User = require('./models/users.model');
let uuidAPIKey = require('uuid-apikey');

let createApiKey = (req, res) => {
    let result = uuidAPIKey.create();
    if (result && result.apiKey) {
        let formattedKey = 'SnX-' + result.apiKey
        return formattedKey;
    } else {
        return res.json({ success: false, msg: 'Error generating Api Key' });
    }
}

let checkIsPremium = async (email) => {
    let result = await User.getUserData(email);
    result = result[0].isPremium;
    return result;
}

let checkIsActive = async (email) => {
    let result = await User.getUserData(email);
    result = result[0].isActive;
    return result;
}



module.exports.checkIsActive = checkIsActive;
module.exports.checkIsPremium = checkIsPremium;
module.exports.createApiKey = createApiKey;
