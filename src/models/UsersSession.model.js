const mongoose = require('mongoose');

let UserSessionSchema = new mongoose.Schema(
    {
        userId: {
            type: String,
            required: true
        },
    },
    {
        timestamps: true
    },
    {
        strict: false,
        collection: 'users.sessions'
    },
    {
        versionKey: false
    }
);

let UserSession = mongoose.model('UserSession', UserSessionSchema, 'users.sessions');
module.exports = UserSession;
