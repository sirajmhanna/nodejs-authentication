const express = require('express');
const route = express.Router();
const TokensControllers = require('../controllers/tokens');

// Validate Access Token Route
route.post('/access/validate', TokensControllers.validateAccessToken);

// Generate Access Token Route
route.post('/refresh', TokensControllers.generateAccessToken);

module.exports = route;
