const GoogleStrategy = require("passport-google-oauth20").Strategy;
const GithubStrategy = require("passport-github2").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const User = require("./models/User");
const GoogleUser = require("./models/GoogleUser");
const GithubUser = require("./models/GithubUser");
const FacebookUser = require("./models/FacebookUser");
const passport = require("passport");
require("dotenv").config();
require("https").globalAgent.options.rejectUnauthorized = false;

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;

FACEBOOK_APP_ID = process.env.FACEBOOK_APP_ID;
FACEBOOK_APP_SECRET = process.env.FACEBOOK_APP_SECRET;


passport.use(
  new GoogleStrategy(
    {
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
    },
    function (accessToken, refreshToken, profile, done) {
      GoogleUser.findOne({ googleId: profile.id }).then((currentUser) => {
        if (currentUser) {
          console.log(`User already exists: `, currentUser);
          return done(null, currentUser);
        } else {
          // Create a new GoogleUser instance with required fields
          const newGoogleUser = new GoogleUser({
            displayName: profile.displayName,
            googleId: profile.id,
            image: profile.photos[0].value, // Set the image field
          });

          newGoogleUser
            .save()
            .then((newUser) => {
              console.log(`New Google User Created:`, newUser);
              return done(null, newUser);
            })
            .catch((error) => {
              console.error(`Error creating new Google User:`, error);
              return done(error, null);
            });
        }
      });
    }
  )
);



passport.use(
  new GithubStrategy(
    {
      clientID: GITHUB_CLIENT_ID,
      clientSecret: GITHUB_CLIENT_SECRET,
      callbackURL: "/auth/github/callback",
    },
    async function (accessToken, refreshToken, profile, done) {
      try {
        // Check if the user with the same GitHub id exists
        const existingUser = await GithubUser.findOne({ githubId: profile.id });

        if (existingUser) {
          console.log("User already exists:", existingUser);
          return done(null, existingUser);
        }

        // Create a new GithubUser instance with required fields
        const newGithubUser = new GithubUser({
          displayName: profile.displayName,
          githubId: profile.id,
        });

        const savedUser = await newGithubUser.save();
        console.log("New Github User Created:", savedUser);
        return done(null, savedUser);
      } catch (error) {
        console.error("Error in Github Passport strategy:", error);
        return done(error, null);
      }
    }
  )
);





passport.use(
  new FacebookStrategy(
    {
      clientID: FACEBOOK_APP_ID,
      clientSecret: FACEBOOK_APP_SECRET,
      callbackURL: "/auth/facebook/callback",
      profileFields: ["id", "displayName"],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Check if the user with the same facebookId exists
        const existingUser = await FacebookUser.findOne({
          facebookId: profile.id,
        });

        if (existingUser) {
          console.log("User already exists:", existingUser);
          return done(null, existingUser);
        }

        // If the user doesn't exist, create a new user in the database
        const newUser = new FacebookUser({
          displayName: profile.displayName,
          facebookId: profile.id,
        });

        const savedUser = await newUser.save();
        console.log("New Facebook User Created:", savedUser);
        return done(null, savedUser);
      } catch (error) {
        console.error("Error in Facebook Passport strategy:", error);
        return done(error, null);
      }
    }
  )
);



passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});
