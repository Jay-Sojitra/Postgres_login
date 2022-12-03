const express = require("express");
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
require("dotenv").config();
const app = express();

const initializePassport = require("./passportConfig")

initializePassport(passport);

const PORT = process.env.PORT || 5000;

app.use(express.urlencoded({ extended: false }));
app.set("view engine", "ejs");

app.use(
    session({
        secret: "secret",

        resave: false,

        saveUninitialized: false
    })
)

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

app.get("/", (req, res) => {
    res.render("index");
})


app.get("/users/register", checkAuthenticated, (req, res) => {
    res.render("register");
})
app.get("/users/login", checkAuthenticated, (req, res) => {
    res.render("login");
})
app.get("/users/dashboard", checkNotAuthenticated, (req, res) => {
    res.render("dashboard", { user: req.user.name });
})
app.get("/users/logout", (req, res) => {
    console.log("hellooooo");
    req.logout;
    res.render("index", { message: "You have logged out successfully" });
});

app.post("/users/register", async (req, res) => {
    let { name, email, password, password2 } = req.body;

    console.log({
        name,
        email,
        password,
        password2
    });

    let errors = [];

    if (!name || !email || !password || !password2) {
        errors.push({ message: 'Please enter all required fields' })
    }
    if (password.length < 6) {
        errors.push({ message: 'Password must be at least 6 characters' })
    }
    if (password != password2) {
        errors.push({ message: 'passwords do not match' })
    }
    if (errors.length > 0) {
        res.render("register", { errors });
    } else {
        hashedPassword = await bcrypt.hash(password, 10);
        console.log(hashedPassword);

        pool.query(
            `SELECT * FROM users
            where email = $1 `,
            [email],
            (err, results) => {
                if (err) {
                    throw err;
                }
                console.log(err);
                if (results.rows.length > 0) {
                    errors.push('email already exists');
                    res.render("register", { errors })
                }
                else {
                    pool.query(
                        `INSERT INTO users (name, email, password) 
                        VALUES ($1, $2, $3)
                        RETURNING id, password`,
                        [name, email, hashedPassword],
                        (err, results) => {
                            if (err) {
                                throw err;
                            }
                            console.log(results.rows);
                            req.flash('success_msg', "You are now registered. Please log in");
                            res.redirect("/users/login");
                        }
                    )
                }
            }

        )

    }


})

app.post('/users/login',
    passport.authenticate("local", {
        successRedirect: "/users/dashboard",
        failureRedirect: "/users/login",
        failureFlash: true
    })
)

function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect("/users/dashboard");
    }
    next();
}

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect("/users/login");
}

app.listen(PORT, () => {
    console.log('listening on port ' + PORT);
});
