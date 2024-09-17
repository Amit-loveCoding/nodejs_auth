const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const flash = require('connect-flash');
const bcrypt = require('bcrypt');
const path = require('path');
const passport = require('passport');
const nodemailer = require('nodemailer');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();
// const User = require('./User/user');


// Define user schema and model
const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        unique: true,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    confirmpassword: {
        type: String,
        required: true,
        validate: {
            validator: function (value) {
                return this.password === value;
            },
            message: 'Password Do not match'
        }
    }
});

const User = mongoose.model('User', UserSchema);

// module.exports = User;
// Connect to MongoDB
mongoose.connect('mongodb://0.0.0.0:27017/nodeauthapp', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});



// Configure app
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: true
}));
app.use(flash());

// Define routes
app.get('/', (req, res) => {
    const user = req.session.user;
    const message = req.flash('message')[0];
    res.render('index', { user, message });
});

app.get('/login', (req, res) => {
    const message = req.flash('message')[0];
    res.render('login', { message });
});



app.post('/login', (req, res) => {
    const { email, password } = req.body;
    User.findOne({ email }, (err, user) => {
        if (err) {
            req.flash('message', 'An error occurred');
            res.redirect('/login');
        } else if (!user) {
            req.flash('message', 'Email or password is incorrect');
            res.redirect('/login');
        } else {
            bcrypt.compare(password, user.password, (err, result) => {
                if (result) {
                    req.session.user = user;
                    res.render('index', { user, message: req.flash('message') });
                } else {
                    req.flash('message', 'Email or password is incorrect');
                    res.redirect('/login');
                }
            });
        }
    });
});

app.get('/reset-password', (req, res) => {
    const { token } = req.params;
    // TODO: Validate the token and render the reset password form
    res.render('reset-password', { token, message: req.flash('message') });
});

app.post('/reset-password', (req, res) => {
    const { token } = req.params;
    const { password, confirmPassword } = req.body;
    // TODO: Validate the password and confirm password fields
    if (password !== confirmPassword) {
        req.flash('message', 'Passwords do not match');
        res.redirect(`/reset-password/${token}`);
        return;
    }
    User.findOneAndUpdate(
        { resetPasswordToken: token },
        { $set: { password: bcrypt.hashSync(password, 10), resetPasswordToken: null } },
        { new: true },
        (err, user) => {
            if (err) {
                req.flash('message', 'An error occurred while resetting your password');
                res.redirect(`/reset-password/${token}`);
            } else {
                req.flash('message', 'Your password has been reset successfully');
                res.redirect('/login');
            }
        }
    );
});

app.get('/forgot-password', (req, res) => {
    const message = req.flash('message')[0];
    res.render('forgot-password', { message });
});

app.post('/forgot-password', (req, res) => {
    const { email } = req.body;
    User.findOne({ email }, (err, user) => {
        if (err) {
            req.flash('message', 'An error occurred');
            res.redirect('/forgot-password');
        } else if (!user) {
            req.flash('message', 'No user with that email address found');
            res.redirect('/forgot-password');
        } else {
            // TODO: Send password reset email to user
            req.flash('message', 'Password reset email sent');
            res.redirect('/forgot-password');
        }
    });
});




app.get('/signup', (req, res) => {
    const message = req.flash('message')[0];
    res.render('signup', { message });
});

app.post('/signup', (req, res) => {
    const { name, email, password, confirmpassword } = req.body;
    User.findOne({ email }, (err, user) => {
        if (err) {
            req.flash('message', 'An error occurred');
            res.redirect('/signup');
        } else if (user) {
            req.flash('message', 'Email already exists');
            res.redirect('/signup');
        } else {
            bcrypt.hash(password, 10, (err, hash) => {
                if (err) {
                    req.flash('message', 'An error occurred');
                    res.redirect('/signup');
                } else {
                    const user = new User({
                        name,
                        email,
                        password: hash,
                        confirmpassword: hash
                    });

                    user.save()
                        .then(() => {
                            req.session.user = user;
                            res.redirect('/');
                        })
                        .catch(err => {
                            if (err.code === 11000) {
                                req.flash('message', 'Email already exists');
                                res.redirect('/signup');
                            } else {
                                req.flash('message', 'An error occurred');
                                res.redirect('/signup');
                            }
                        });
                }
            });
        }
    });
});

app.get('/logout', (req, res) => {
    req.session.user = undefined;
    res.redirect('/');
});

app.post('/logout', (req, res) => {
    res.redirect('/');
})

app.get('/home', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});
app.get('/about', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'about.html'));
});
app.get('/contact', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'contact.html'));
});


// Start server
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
