const express = require('express');
const path = require('path');
const db = require('./config/connection');

// initialize a new Express app
const app = express();
const PORT = process.env.PORT || 3001;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// if we are in production mode, client/build as static assets
if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.join(__dirname, '../client/build')));
}

db.once('open', () => {
    app.listen(PORT, () => console.log(`Now listening on localhost:${PORT}`))
})