//jshint esversion:6
require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const pg = require("pg");
const crypto = require("crypto");

const iv = process.env.IV;
function generateEncryptionKey(key) {
  const hash = crypto.createHash('sha256');
  hash.update(key, 'utf8');
  return hash.digest('hex').slice(0, 32);
}

// AES-256 암호화 함수
function encrypt(text, key) {
  //const cipher = crypto.createCipheriv('aes-256-cbc', key, crypto.randomBytes(16));
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

// AES-256 복호화 함수
function decrypt(encryptedText, key) {
  //const decipher = crypto.createDecipheriv('aes-256-cbc', key, crypto.randomBytes(16));
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

const enteredkey = process.env.KEY; // 32바이트(256비트)의 암호화 키

let encryptionKey = generateEncryptionKey(enteredkey);

const db = new pg.Client({
    user: "postgres",
    host: "localhost",
    database: "userDB",
    password: "kim7664",
    port: 5432,
});

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
    extended: true
}));

db.connect();

app.get("/", function(req, res) {
    res.render("home");
});

app.get("/login", function(req, res) {
    res.render("login");
});

app.get("/register", function(req, res) {
    res.render("register");
});

app.post("/register", async function(req, res) {
    const email = req.body.username;
    const password = req.body.password;

    const encryptPassword = encrypt(password, encryptionKey);
    const decryptedPassword = decrypt(encryptPassword, encryptionKey);

    console.log(decryptedPassword);


    try {
        const result = await db.query("insert into users(email, password) values($1, $2)"
            , [email, encryptPassword]
        ); 

      res.render("secrets");
    } catch(err) {
        console.log(err);
        res.redirect("/");
    }
});

app.post("/login", async function(req, res) {
    const email = req.body.username;
    const password = req.body.password;

    try {
        const result = await db.query("select * from users where email = $1", [email]);

        if(result.rows.length > 0) {
            const encryptedText = result.rows[0].password;  
            const decryptedPassword = decrypt(encryptedText, encryptionKey);

            if(password === decryptedPassword) {
                res.render("secrets");
            } else {
                res.redirect("/");
            }
        } else {
            res.redirect("/");
        }
    } catch(err) {
        console.log(err);
    }
});

app.get("/secrets", function(req, res) {
    res.render("secrets");
});

app.get("/submit", function(req, res) {
    res.render("submit");
});

app.listen(3000, function() {
    console.log("Server started on port 3000.");
});