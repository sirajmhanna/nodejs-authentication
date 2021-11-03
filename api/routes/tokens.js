const express = require('express');
const route = express.Router();
const TokensControllers = require('../controllers/tokens');

// Validate Access Token Route
route.post('/access/validate', TokensControllers.validateAccessToken);

module.exports = route;
