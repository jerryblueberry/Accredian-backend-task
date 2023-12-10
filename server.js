const express = require('express');
const cors = require('cors');
const mysql = require('mysql');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const salt = 10;
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors({
    origin: true,
    methods: ['POST', 'GET', 'OPTIONS'],
    credentials: true,
}));
app.use(cookieParser());

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'signup',
});

const verifyUser = (req, res, next) => {
    const token = req.cookies.token;
    console.log('Received Token:', token);

    if (!token) {
        return res.json({ Error: 'You are not Authenticated' });
    } else {
        jwt.verify(token,process.env.JWT_SECRET_KEY, (err, decoded) => {
            if (err) {
                return res.json({ Error: 'Token is not verified' });
            } else {
                req.name = decoded.name;
                next();
            }
        });
    }
};

// endpoint to fetch logged in user name
app.get('/', verifyUser, (req, res) => {
    return res.json({ Status: 'Success', name: req.name });
});

// endpoint for register
app.post('/sign-up', (req, res) => {
    const checkEmailQuery = 'SELECT * FROM login WHERE email = ?';

    db.query(checkEmailQuery, [req.body.email], (checkErr, checkResult) => {
        if (checkErr) {
            return res.json({ Error: 'Error checking email existence' });
        }

        if (checkResult.length > 0) {
            return res.json({ Error: 'Email already exists' });
        }

        // Continue with the registration process
        const insertQuery = 'INSERT INTO login(`name`,`email`,`password`) VALUES(?)';
        bcrypt.hash(req.body.password.toString(), salt, (hashErr, hash) => {
            if (hashErr) return res.json({ Error: 'Error for hashing password' });
            const values = [
                req.body.name,
                req.body.email,
                hash
            ];
            db.query(insertQuery, [values], (insertErr, result) => {
                if (insertErr) return res.json({ Error: 'Inserting data Error in server' });
                return res.json({ Status: 'Success' });
            });
        });
    });
});



app.post('/login', (req, res) => {
    const sql = 'SELECT * FROM login WHERE email = ?';
    db.query(sql, [req.body.email], (err, data) => {
      if (err) return res.json({ Error: "Login error in Server" });
      if (data.length > 0) {
        bcrypt.compare(req.body.password.toString(), data[0].password, (err, response) => {
          if (err) return res.json({ Error: "Password Compare Error" });
          if (response) {
            const name = data[0].name;
            const token = jwt.sign({ name }, process.env.JWT_SECRET_KEY, { expiresIn: '1d' });
            res.cookie('token', token, { httpOnly: true, sameSite: 'none', secure: true });
            return res.json({ Status: "Success", token }); // Send the token in the response
          } else {
            return res.json({ Error: "Password" });
          }
        });
      } else {
        return res.json({ Error: "No email existed" });
      }
    });
  });
  

//    logout endpoint
app.get('/logout',(req,res) => {
    res.clearCookie('token');
    return res.json({Status:"Success"});
})


app.listen(8000, () => {
    console.log('Running on Port 8000');
});
