const LocalStrategy = require('passport-local').Strategy;
const { pool } = require('./dbConfig');
const bcrypt = require('bcrypt');

function initialize(passport) {

    const authenticateUser = (email, password, done) => {
        console.log(email, password);
        pool.query(
            `SELECT * FROM users WHERE email = $1`,
            [email],
            (err, results) => {
                if (err) {
                    throw err;
                }
                console.log(results.rows);
                if (results.rows.length > 0) {
                    const user = results.rows[0];
                    console.log('user', user);
                    bcrypt.compare(password, user.password, (err, isMatch) => {
                        if (err) {
                            throw err;
                        }
                        if (isMatch) {
                            return done(null, user);

                        } else {
                            return done(null, false, { message: 'Password is not correct' });
                        }
                    });
                } else {
                    return done(null, false, { message: 'email is not Registered' });
                }
            }
        )
    };

    passport.use(
        new LocalStrategy({
            usernameField: 'email',
            passwordField: 'password'
        },
            authenticateUser
        )
    );

    // Stores user details inside session. serializeUser determines which data of the user
    // object should be stored in the session. The result of the serializeUser method is attached
    // to the session as req.session.passport.user = {}. Here for instance, it would be (as we provide
    //   the user id as the key) req.session.passport.user = {id: 'xyz'}
    passport.serializeUser((user, done) => { //store the user id in session cookie
        done(null, user.id);
    });

    // In deserializeUser that key is matched with the in memory array / database or any data resource.
    // The fetched object is attached to the request object as req.user
    passport.deserializeUser((id, done) => { // use the id which store in session cookie
        pool.query(`SELECT * FROM users WHERE id =$1`, [id], (err, results) => {
            if (err) {
                return done(err);
            }
            console.log(`ID is ${results.rows[0].id}`);
            return done(null, results.rows[0]);
        });
    });


}

module.exports = initialize;
