const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const User = require('./models/user');

const app = express();

const urlencodedParser = bodyParser.urlencoded({ extended: false });
app.use(bodyParser.json(), urlencodedParser);

//connect to mongodb database
const dbURI = "mongodb+srv://robavelii:robavelii@cluster0.mfyt0.mongodb.net/myFirstDatabase?retryWrites=true&w=majority"

mongoose.connect(dbURI, { useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false }).then((res) =>{
    app.listen(process.env.PORT, () => console.log("Server is running on port " + process.env.PORT)).catch(err => console.log(err));
})

app.post("/register", async (req, res) => {
    const user = req.body;

    //check if user already exists
    const takenUsername = await User.findOne({ username: user.username });
    const takenEmail = await User.findOne({ email: user.email });
    
    if(takenUsername || takenEmail){
        res.json({message: "Username or email already taken"})
    } else {
        user.password = await bcrypt.hash(req.body.password, 10);

        const dbUser = new User({
            username: user.username.toLowerCase(),
            email: user.email.toLowerCase(),
            password: user.password
        })

        dbUser.save()
        res.json({message: "User created"})

    }
})

app.post("/login", (req, res) => {
    const userLoggingIn = req.body;
    
    User.findOne({ username: userLoggingIn.username})
    .then(dbUser => {
        if(!dbUser){
            return res.json({
                message: "Invalid Username or Password"
        })
    }
    bcrypt.compare(userLoggingIn.password, dbUser.password)
    .then(isCorrect => {
        if(isCorrect){
            const payload = {
                id:dbUser._id,
                username: dbUser.username
            }
            jwt.sign(
                payload,
                process.env.JWT_SECRET,
                {expiresIn: "3h"},
                (err, token) => {
                    if(err) return res.json({message: err})
                    return res.json({
                        message: "Logged in",
                        token: "Bearer " + token
                    })
                }
            )
        } else {
            return res.json({message: "Invalid Username or Password"})
            }
        })
    })
})