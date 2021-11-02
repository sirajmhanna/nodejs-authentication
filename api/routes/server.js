const express = require('express');
const route = express.Router();
const ServerControllers = require('../controllers/server');

// Server Health Route
route.get('/health', ServerControllers.health);

module.exports = route;
