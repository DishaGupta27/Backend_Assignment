const jwt = require('jsonwebtoken');
const BlacklistedToken = require('../models/BlacklistedToken');
require('dotenv').config();

const auth = async (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'No token provided' });

    const blacklisted = await BlacklistedToken.findOne({ token });
    if (blacklisted) return res.status(401).json({ message: 'Token blacklisted' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ message: 'Invalid token' });
    }
};

module.exports = auth;
