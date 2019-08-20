// DOTENV CONFIG
require('dotenv').config();

/**
 * Module dependencies.
 */
const express = require('express');
const app = express();
const compression = require('compression');
const session = require('express-session');
const bodyParser = require('body-parser');
const winston = require('winston')
const logger = require('morgan');
const cookieParser = require('cookie-parser');
const lusca = require('lusca');
const MongoStore = require('connect-mongo')(session);
const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');

// Socket
let server = require('http').Server(app);
// let io = require('socket.io')(server);

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/views/index.html');
});


// middleware
const mid = require('./middleware');
const validateTkn = mid.verifyToken;

//  logger
// const log = require('./services/logger.service');
let log = require('./services/logger.service');
let streams = require('./services/logger.service').logger;

/**
 * DB Config and Connection
 */

let mongoConnectionString;

process.env.NODE_ENV == 'development' ? mongoConnectionString = `mongodb://${process.env.MONGO_HOST}:${process.env.MONGO_PORT}/${process.env.MONGO_DB}` : mongoConnectionString = `mongodb://${process.env.MONGO_USER}:${process.env.MONGO_PASS}@${process.env.MONGO_HOST}:${process.env.MONGO_PORT}/${process.env.MONGO_DB}`;

// mongoose.Promise = global.Promise;

mongoose.connect(
    mongoConnectionString, {
        useNewUrlParser: true,
        useCreateIndex: true,
        useFindAndModify: false,
        reconnectTries: Number.MAX_VALUE, // Never stop trying to reconnect
        reconnectInterval: 500, // Reconnect every 500ms
        poolSize: 10, // Maintain up to 10 socket connections
    },
    err => {
        if (err) {
            // log.error(err);
            log('error', err);
        } else {
            log('info', `Connection to Database: ${process.env.MONGO_DB} Successfull`);
            // log.info(`Connection to Database: ${process.env.MONGO_DB} Successfull`)
        }
    }
);

/**
 * Routers
 */

const auth = require('./controllers/Authentication');
const test = require('./controllers/Testing');
const users = require('./controllers/Users');


// var requestStream = fs.createWriteStream(path.join(__dirname, 'logs/requests.log'), { flags: 'a' })


// app.use(compression());
// app.use(logger('combined', { stream: requestStream }));

app.use(logger('combined', { stream: streams.stream }))
app.use(bodyParser.json());
app.use(
    bodyParser.urlencoded({
        extended: true
    })
);

app.enable('trust proxy', true)

app.use(cookieParser());
app.use(
    session({
        resave: true,
        saveUninitialized: true,
        secret: process.env.SESSION_SECRET,
        cookie: {
            maxAge: 30 * 24 * 60 * 60 * 1000
        },
        store: new MongoStore({
            mongooseConnection: mongoose.connection,
            autoReconnect: true,
        })
    })
);


app.use(lusca.xframe('SAMEORIGIN'));
app.use(lusca.xssProtection(true));
app.disable('x-powered-by');

/**
 * CORS
 */

app.use((req, res, next) => {
    req.userip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS, POST, PUT, DELETE');
    res.header(
        'Access-Control-Allow-Headers',
        'Origin, X-Requested-With, authtoken, contentType, Content-Type, authorization'
    );
    next();
});

/**
 * API Urls
 */
app.use('/api/v1', auth);
// app.use(validateTkn);
app.use('/api/v1', users);
app.use('/api/v1', test);



// io.on('connection', function (socket) {

//     // console.log('a user connected');

//     // socket.on('disconnect', function () {
//     //     console.log('user disconnected');
//     // });

//     socket.on('sending message', (message) => {
//         console.log('Message is received :', message);

//         if (message == 'HHH') {
//             io.emit('new message', {message: 'Intent Success'});
//         } else {
//             io.emit('new message', {message: 'No Intent'});

//         }


//      });
// });


app.options('*', (req, res) => {
    res.end();
});

/**
 * Error Handler.
 */
// app.use(function (err, req, res, next) {
//     // set locals, only providing error in development
//     res.locals.message = err.message;
//     res.locals.error = process.env.NODE_ENV === 'development' ? err : {};

//     // add this line to include winston logging
//     log('error', `${err.status || 500} - ${err.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
//     // log.error(`${err.status || 500} - ${err.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
//     res.status(err.status || 500);
// });


/**
 * Uncaught Exceptions and Unhandled Rejections Handler
 */
process.on('unhandledRejection', (reason, rejectedPromise) => {
    // log.error('rejection', reason);
    // log.error('rejection', rejectedPromise);
    log('error', `${reason}`);
    throw reason;
});

process.on('uncaughtException', err => {
    log('error', `${err.message}, ${err.stack}`);
    // log.error(err.message, err.stack);
    process.exit(1);
});

// 404 handler

app.use((req, res) => {
    res.status(404).json({
        error: 1,
        message: 'URL Not Found'
    });
});

process.env.NODE_ENV == 'development' ? process.env.DOMAIN = 'localhost' : process.env.DOMAIN


server.listen(process.env.PORT, () => {
    log('info', `app is running at DOMAIN: ${process.env.DOMAIN},  PORT: ${process.env.PORT}, ENVIRNOMENT: ${process.env.NODE_ENV}`)
    // log.info(`app is running at DOMAIN: ${process.env.DOMAIN},  PORT: ${process.env.PORT}, ENVIRNOMENT: ${process.env.NODE_ENV}`);
});
