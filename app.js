const express = require('express');
const app = express();
const apiRoutes = require('./routes/api');

app.use('/api', apiRoutes); 