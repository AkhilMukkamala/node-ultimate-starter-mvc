//  Library
const argon2 = require("argon2");
const {
    randomBytes,
    createHash
} = require("crypto");
const jwt = require("jsonwebtoken");
const Ajv = require("ajv");
const ajv = new Ajv({
    $data: true
});
const speakeasy = require("speakeasy");
const qrCode = require("qrcode");

//  Custom Files

const log = require("./Logger.service");
const msg = require("../config/msg.config");
const CommonService = require("./Common.service");
const customMail = require("./Mailer.service").customMail;

const Users = require("../models/Users.model");
const UsersMeta = require("./../models/UsersMeta.model");
const UsersReferral = require("./../models/UsersReferral.model");

// Email Templates
const emailTemplates = require('../emails/templates');

// Services

let signUp = async (name, email, password) => {
    try {
        const valid = ajv.validate(signUpSchema, {
            name,
            email,
            password
        });
        if (!valid) {
            return CommonService.formatResponse(false, {
                message: msg["required-fields-missing"],
                error: JSON.stringify(ajv.errors[0])
            });
        } else {
            // Check User If Already Registered
            const isUserRegistered = await Users.findOne({
                email
            }, {
                createdAt: 0,
                updatedAt: 0,
                __v: 0
            }).exec();

            if (isUserRegistered) {
                return CommonService.formatResponse(false, {
                    message: msg["user-registered"],
                    error: null
                });
            } else {
                const hashedPassword = await generatePasswordHash(password);
                //  Save User
                let user = await Users.create({
                    name: name,
                    email: email,
                    password: hashedPassword
                    // TODO Referral
                    // referral: CommonService.generateReferralCode(),
                    // referredBy: referredBy
                });

                // Send Welcome Email
                commonEmailTemplate(email, name, email, `Welcome to ${process.env.APPNAME}`, msg["welcome-email"]);

                //  Send Verification Email
                await sendVerificationEmail(user._id);

                return CommonService.formatResponse(true, {
                    message: msg["user-registration-success"]
                });
            }
        }
    } catch (error) {
        log("error", `${error}`);
        return CommonService.formatResponse(false, {
            message: msg["something-went-wrong"],
            error: error
        });
    }
};

let signIn = async (email, password) => {
    try {
        // Schema Validation
        const valid = ajv.validate(signInSchema, {
            email,
            password
        });

        if (!valid) {
            return CommonService.formatResponse(false, {
                message: msg["required-fields-missing"],
                error: JSON.stringify(ajv.errors[0])
            });
        } else {
            // Check If Email Exists or Not.
            const isUserRegistered = await Users.findOne({
                email
            }, {
                password: 1
            }).exec();

            if (!isUserRegistered) {
                return CommonService.formatResponse(false, {
                    message: msg["user-not-registered"],
                    error: null
                });
            } else {
                const userPassword = isUserRegistered.password;
                const userId = isUserRegistered._id;

                const isPasswordCorrect = await argon2.verify(
                    userPassword,
                    password
                );

                if (!isPasswordCorrect) {
                    return CommonService.formatResponse(false, {
                        message: msg["incorrect-password"],
                        error: null
                    });
                } else {
                    // Check if 2FA Enabled!
                    const is2FAEnabled = await UsersMeta.findOne({
                        userId
                    }).exec();

                    if (is2FAEnabled && is2FAEnabled.security.twoFactor.gAuth.enabled) {
                        return CommonService.formatResponse(true, {
                            message: msg["twofactor-enabled"]
                        });
                    } else {
                        // Generate JWT
                        // Frontend should send "_id" everytime via an API Call, To get user details. (Security Measure!)
                        const token = generateJWT({
                            user: userId
                        });
                        return CommonService.formatResponse(true, {
                            message: msg["twofactor-disabled"],
                            data: {
                                token
                            }
                        });
                    }
                }
            }
        }
    } catch (error) {
        log("error", `${error}`);
        return CommonService.formatResponse(false, {
            message: msg["something-went-wrong"],
            error: error
        });
    }
};

let generateJWT = user => {
    return jwt.sign(user, process.env.JWT_SECRET, {
        expiresIn: "3h"
    });
};

let getQrGAuth = async userId => {
    try {
        if (!userId) {
            return CommonService.formatResponse(false, {
                message: msg["required-fields-missing"],
                error: null
            });
        } else {
            const is2FAEnabled = await UsersMeta.findOne({
                userId
            }, {
                security: 1
            }).exec();
            const gAuthenticator = is2FAEnabled.security.twoFactor.gAuth.data;
            if (gAuthenticator) {
                const qr = await qrCode.toDataURL(gAuthenticator.otpauth_url);
                const response = {
                    qr: qr
                };
                return CommonService.formatResponse(true, {
                    message: msg["qr-retrieved"],
                    data: response
                });
            } else {
                return CommonService.formatResponse(false, {
                    message: msg["2fa-disabled"],
                    error: null
                });
            }
        }
    } catch (error) {
        log("error", `${error}`);
        return CommonService.formatResponse(false, {
            message: msg["something-went-wrong"],
            error: error
        });
    }
};

let setupGAuth = async userId => {
    try {
        if (!userId) {
            return CommonService.formatResponse(false, {
                message: msg["required-fields-missing"],
                error: null
            });
        } else {
            const isUser = await Users.findById(userId, {
                _id: 1
            }).exec();
            if (!isUser) {
                return CommonService.formatResponse(false, {
                    message: msg["user-not-found"],
                    error: null
                });
            } else {
                const secret = speakeasy.generateSecret({
                    length: 30
                });
                const updateGAuthData = await UsersMeta.updateOne({
                    userId
                }, {
                    "security.twoFactor.gAuth.data": secret,
                    "security.twoFactor.gAuth.enabled": true
                }, {
                    upsert: true,
                    new: true
                }).exec();
                const qr = await qrCode.toDataURL(secret.otpauth_url);
                let response = {
                    qr: qr,
                    base32: secret.base32
                };
                return CommonService.formatResponse(true, {
                    message: msg["qr-generated"],
                    data: response
                });
            }
        }
    } catch (error) {
        log("error", `${error}`);
        return CommonService.formatResponse(false, {
            message: msg["something-went-wrong"],
            error: error
        });
    }
};

let verifyGAuth = async (userId, token) => {
    try {
        const gAuthData = await UsersMeta.findOne({
            userId
        }, {
            "security.twoFactor": 1
        }).exec();
        if (gAuthData && gAuthData.security.twoFactor.gAuth.enabled) {
            const isOTPCorrect = speakeasy.totp.verify({
                secret: gAuthData.security.twoFactor.gAuth.data.base32,
                encoding: "base32",
                token: token,
                window: 3
            });
            if (isOTPCorrect) {
                // Generate JWT
                // Frontend should send "_id" everytime via an API Call, To get user details. (Security Measure!)
                const token = generateJWT({
                    user: userId
                });
                return CommonService.formatResponse(true, {
                    message: msg["twofactor-success"],
                    data: {
                        token
                    }
                });
            } else {
                return CommonService.formatResponse(false, {
                    message: msg["twofactor-failed"],
                    error: null
                });
            }
        } else {
            return CommonService.formatResponse(false, {
                message: msg["user-not-found-or-2fa-disabled"],
                error: null
            });
        }
    } catch (error) {
        log("error", `${error}`);
        return CommonService.formatResponse(false, {
            message: msg["something-went-wrong"],
            error: error
        });
    }
};

let changePassword = async (_id, oldPassword, newPassword, confirmPassword) => {
    try {
        const valid = ajv.validate(changePasswordSchema, {
            _id,
            oldPassword,
            newPassword,
            confirmPassword
        });

        if (!valid) {
            return CommonService.formatResponse(false, {
                message: msg["required-fields-missing"],
                error: JSON.stringify(ajv.errors[0])
            });
        } else {
            const isUserExist = await Users.findById(_id, {
                password: 1
            }).exec();

            if (!isUserExist) {
                return CommonService.formatResponse(false, {
                    message: msg["user-not-found"],
                    error: null
                });
            } else {
                const userPassword = isUserExist.password;

                const isPasswordCorrect = await argon2.verify(
                    userPassword,
                    oldPassword
                );

                if (!isPasswordCorrect) {
                    return CommonService.formatResponse(false, {
                        message: msg["incorrect-old-password"],
                        error: null
                    });
                } else {
                    const hashedPassword = await generatePasswordHash(newPassword);

                    //  Update New Password
                    let updatedPassword = await Users.updateOne({
                        _id
                    }, {
                        $set: {
                            password: hashedPassword
                        }
                    }, {
                        new: true
                    }).exec();

                    return CommonService.formatResponse(true, {
                        message: msg["password-updated"]
                    });
                }
            }
        }
    } catch (error) {
        log("error", `${error}`);
        return CommonService.formatResponse(false, {
            message: msg["something-went-wrong"],
            error: error
        });
    }
};

let generatePasswordHash = async password => {
    //  Generate Salt
    const salt = randomBytes(32).toString("hex");

    // Argon Options
    const options = {
        timeCost: 4,
        memoryCost: 1 << 14,
        parallelism: 2,
        hashLength: 64
    };
    // Generate Password Hash
    const hashedPassword = await argon2.hash(password, salt, options);
    return hashedPassword;
};

let sendVerificationEmail = async (_id) => {
    try {
        // Get User!
        let user = await Users.findById(_id, {
            name: 1,
            email: 1
        }).exec();

        // Generate Email Verification Link

        let randomToken = randomBytes(32).toString("hex");
        randomToken = createHash('sha1').update(randomToken + _id).digest('hex');

        let updateEmailVerificationTkn = await UsersMeta.updateOne({
            userId: _id,
        }, {
            'isEmailSent': true,
            'tokens.emailVerification': randomToken
        }, {
            upsert: true,
            new: true
        }).exec();

        let url = `${process.env.DOMAIN_V1}` + '/email-verification/' + `${randomToken}`;

        // Send Verification Email
        commonEmailTemplate(user.email, user.name, user.email, `Welcome to ${process.env.APPNAME}`, msg["account-verification-email"], url, 'VERIFY EMAIL');
        return CommonService.formatResponse(true, {
            message: msg["email-sent"]
        });
    } catch (error) {
        log("error", `${error}`);
        return CommonService.formatResponse(false, {
            message: msg["something-went-wrong"],
            error: error
        });
    }
};

let checkEmailVerificationStatus = async (token) => {
    try {
        let query = await UsersMeta.findOne({
            'tokens.emailVerification': token
        }, {
            'tokens': 1
        }).exec();

        if (query) {
            await UsersMeta.findOneAndUpdate({
                'tokens.emailVerification': token
            }, {
                isEmailSent: true
            }, {
                new: true
            }).exec();
            return CommonService.formatResponse(true, {
                message: msg["redirect-true"]
            });
        } else {
            return CommonService.formatResponse(false, {
                message: msg["redirect-false"],
                error: null
            });
        }
    } catch (error) {
        log("error", `${error}`);
        return CommonService.formatResponse(false, {
            message: msg["something-went-wrong"],
            error: error
        });
    }
};

let sendPasswordResetEmail = async (email) => {
    try {
        let isUser = await Users.findOne({
            email
        }).exec();

        log('info', isUser);

        if (!isUser) {
            return CommonService.formatResponse(false, {
                message: msg["user-not-found"],
                error: null
            });
        } else {
            // ** Always Upsert this!
            // ! Don't remove the upsert.
            let randomToken = randomBytes(32).toString("hex");
            randomToken = createHash('sha1').update(randomToken + isUser._id).digest('hex');

            await UsersMeta.findOneAndUpdate({
                userId: isUser._id
            }, {
                'tokens.passwordReset': randomToken,
                'tokens.passwordResetExpires': Date.now() + 86400000
            }, {
                upsert: true,
                new: true
            });

            let url = `${process.env.DOMAIN_V1}` + '/reset-password/' + `${randomToken}`;

            // Send Password Reset Email
            commonEmailTemplate(isUser.email, isUser.name, isUser.email, `Password reset request to ${process.env.APPNAME}`, msg["reset-password-email"], url, 'RESET PASSWORD');
            return CommonService.formatResponse(true, {
                message: msg["email-sent"]
            });
        }
    } catch (error) {
        log("error", `${error}`);
        return CommonService.formatResponse(false, {
            message: msg["something-went-wrong"],
            error: error
        });
    }
};

let checkPasswordResetStatus = async (token) => {
    try {
        let query = await UsersMeta.findOne({
            'tokens.passwordReset': token,
            'tokens.passwordResetExpires': {
                $gt: Date.now()
            }
        }, {
            'tokens': 1
        }).exec();

        if (query) {
            // commonEmailTemplate()
            return CommonService.formatResponse(true, {
                message: msg["redirect-true"]
            });
        } else {
            return CommonService.formatResponse(false, {
                message: msg["redirect-false"],
                error: null
            });
        }
    } catch (error) {
        log("error", `${error}`);
        return CommonService.formatResponse(false, {
            message: msg["something-went-wrong"],
            error: error
        });
    }
};

let resetPassword = async (_id, newPassword, confirmPassword) => {
    try {
        const valid = ajv.validate(resetPasswordSchema, {
            _id,
            newPassword,
            confirmPassword
        });

        if (!valid) {
            return CommonService.formatResponse(false, {
                message: msg["required-fields-missing"],
                error: JSON.stringify(ajv.errors[0])
            });
        } else {
            const isUserExist = await Users.findById(_id).exec();

            if (!isUserExist) {
                return CommonService.formatResponse(false, {
                    message: msg["user-not-found"],
                    error: null
                });
            } else {
                const hashedPassword = await generatePasswordHash(newPassword);

                const user = isUserExist;

                //  Update New Password
                let updatedPassword = await Users.updateOne({
                    _id
                }, {
                    $set: {
                        password: hashedPassword
                    }
                }, {
                    new: true
                }).exec();

                commonEmailTemplate(user.email, user.name, user.email, `Password Changed`, msg["password-updated"]);

                return CommonService.formatResponse(true, {
                    message: msg["password-updated"]
                });
            }
        }
    } catch (error) {
        log("error", `${error}`);
        return CommonService.formatResponse(false, {
            message: msg["something-went-wrong"],
            error: error
        });
    }
};



// Mailers

let commonEmailTemplate = (email, title, subtitle, subject, message, url, buttonName) => {
    let args = {
        from: process.env.APPNAME,
        to: email,
        subject: subject,
        html: emailTemplates.commonTemplate(title, subtitle, message, url, buttonName)
    };
    return customMail(args);
};

module.exports.signUp = signUp;
module.exports.signIn = signIn;
module.exports.generateJWT = generateJWT;
module.exports.setupGAuth = setupGAuth;
module.exports.verifyGAuth = verifyGAuth;
module.exports.getQrGAuth = getQrGAuth;
module.exports.changePassword = changePassword;
module.exports.sendVerificationEmail = sendVerificationEmail;
module.exports.checkEmailVerificationStatus = checkEmailVerificationStatus;
module.exports.sendPasswordResetEmail = sendPasswordResetEmail;
module.exports.checkPasswordResetStatus = checkPasswordResetStatus;
module.exports.resetPassword = resetPassword;

// Validations

let checkUserSchema = {
    type: "object",
    required: ["email"],
    properties: {
        email: {
            type: "string",
            format: "email",
            maxLength: 256
        }
    },
    additionalProperties: false
};

let signUpSchema = {
    type: "object",
    required: ["name", "email", "password"],
    properties: {
        name: {
            type: "string",
            minLength: 6
        },
        email: {
            type: "string",
            format: "email",
            maxLength: 256
        },
        password: {
            type: "string",
            minLength: 6
        }
    },
    additionalProperties: false
};

let signInSchema = {
    type: "object",
    required: ["email", "password"],
    properties: {
        email: {
            type: "string",
            format: "email",
            maxLength: 256
        },
        password: {
            type: "string",
            minLength: 6
        }
    },
    additionalProperties: false
};

let changePasswordSchema = {
    type: "object",
    required: ["_id", "oldPassword", "newPassword", "confirmPassword"],
    properties: {
        _id: {
            type: "string"
        },
        oldPassword: {
            type: "string",
            minLength: 6
        },
        newPassword: {
            type: "string",
            minLength: 6
        },
        confirmPassword: {
            const: {
                "$data": "1/newPassword"
            }
        }
    },
    additionalProperties: false
};

let resetPasswordSchema = {
    type: "object",
    required: ["_id", "newPassword", "confirmPassword"],
    properties: {
        _id: {
            type: "string"
        },
        newPassword: {
            type: "string",
            minLength: 6
        },
        confirmPassword: {
            const: {
                "$data": "1/newPassword"
            }
        }
    },
    additionalProperties: false
};
