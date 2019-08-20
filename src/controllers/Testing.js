const express = require('express');
const router = express.Router();
const log = require('../services/logger.service');

router.get('/test', (req, res) => {
    return res.status(200).json({
        success: true,
        data: 'Yes!'
    })
})

module.exports = router;
