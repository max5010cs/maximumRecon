// server.js
const express = require('express');
const cors = require('cors');
const app = express();
const scanRouter = require('./scanRouter');

app.use(cors());
app.use(express.json()); // Parse incoming JSON
app.use('/scan', scanRouter); // Use scan routes

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Scan server running on port ${PORT}`);
});