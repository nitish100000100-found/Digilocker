const express = require("express");
const mongoose = require("mongoose");
const { body, validationResult } = require("express-validator");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const MongoDBStore = require("connect-mongodb-session")(session);
const multer = require("multer");
const path = require("path");

const DB_URL =
  "mongodb+srv://nkdabur7:root@cluster0.hrebfsr.mongodb.net/digi?appName=Cluster0";

const User = require("./user.js");

const app = express();

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${req.params.username}_${req.body.docName}${ext}`);
  },
});

const upload = multer({ storage });

app.set("view engine", "ejs");
app.set("views", "views");

const store = new MongoDBStore({
  uri: DB_URL,
  collection: "sessions",
});

app.use(
  session({
    secret: "trytry",
    resave: false,
    saveUninitialized: true,
    store,
  })
);

app.use((req, res, next) => {
  req.isLoggedIn = req.session.isLoggedIn;
  next();
});

app.use(express.urlencoded({ extended: true }));
app.use(express.static("uploads"));
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.render("homepage", { errors: [] });
});

app.post("/signinsubmit", async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });

    if (!user) {
      return res.status(400).render("homepage", {
        errors: ["User not found "],
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).render("homepage", {
        errors: ["Password not correct "],
      });
    }

    req.session.isLoggedIn = true;
    req.session.username = user.username;

    res.redirect("/digilocker");
  } catch (err) {
    res.status(500).json({
      message: "Signin not successful ❌",
      error: err.message,
    });
  }
});

app.get("/digilocker", async (req, res) => {
  if (!req.isLoggedIn) {
    return res.redirect("/");
  }

  try {
    const username = req.session.username;

    const user = await User.findOne({ username }).lean();

    const excludedFields = ["_id", "username", "password", "__v"];

    const keys = Object.keys(user).filter(
      (key) => !excludedFields.includes(key)
    );

    res.render("digilocker", {
      keys,
      username,
    });
  } catch (err) {
    console.log(err);
    res.status(500).send("Something went wrong");
  }
});

app.get("/signup", (req, res) => {
  res.render("signup", { errors: [] });
});

app.get("/logout", (req, res) => {
  if (!req.isLoggedIn) {
    return res.redirect("/");
  }

  req.session.isLoggedIn = false;

  res.render("homepage", { errors: [] });
});

app.post(
  "/signup",
  [
    body("name").notEmpty().withMessage("Name can't be empty"),
    body("username").notEmpty().withMessage("Username can't be empty"),
    body("password")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 characters"),
    body("confirm_password").custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error("Password and Confirm Password do not match");
      }
      return true;
    }),
  ],
  (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(422).render("signup", {
        errors: errors.array().map((err) => err.msg),
      });
    } else {
      const { username, password } = req.body;

      bcrypt
        .hash(password, 12)
        .then((pass) => {
          const user = new User({ username, password: pass });
          return user.save();
        })
        .then(() => {
          res.redirect("/");
        })
        .catch(() => {
          return res.status(422).render("signup", {
            errors: ["User already exist with this name"],
          });
        });
    }
  }
);

app.get("/changepassword/:username", (req, res) => {
  if (!req.isLoggedIn) {
    return res.redirect("/");
  }

  const username = req.params.username;

  res.render("changepass", {
    username,
    errors: [],
  });
});

app.post(
  "/change-password",
  [
    body("oldPassword")
      .trim()
      .notEmpty()
      .withMessage("Previous password is required"),
    body("newPassword")
      .trim()
      .notEmpty()
      .withMessage("New password is required")
      .isLength({ min: 6 })
      .withMessage("New password must be at least 6 characters long"),
    body("confirmPassword")
      .trim()
      .notEmpty()
      .withMessage("Please confirm your new password")
      .custom((value, { req }) => {
        if (value !== req.body.newPassword) {
          throw new Error("New password and confirm password must match");
        }
        return true;
      }),
  ],
  async (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.render("changepass", {
        username: req.session.username,
        errors: errors.array().map((err) => err.msg),
      });
    }

    try {
      const username = req.session.username;

      const user = await User.findOne({ username });

      const isMatch = await bcrypt.compare(
        req.body.oldPassword,
        user.password
      );

      if (!isMatch) {
        return res.render("changepass", {
          username,
          errors: ["The password which you entered was not correct"],
        });
      }

      const hashedPassword = await bcrypt.hash(req.body.newPassword, 12);

      user.password = hashedPassword;

      await user.save();

      res.redirect("/digilocker");
    } catch (err) {
      console.log(err);
      res.send("Something went wrong");
    }
  }
);

app.get("/addpass/:username", (req, res) => {
  if (!req.isLoggedIn) {
    return res.redirect("/");
  }

  const username = req.params.username;

  res.render("addpass", { username, errors: [] });
});

app.post(
  "/adddpass/:username",
  [
    body("key").trim().notEmpty().withMessage("Key cannot be empty"),
    body("value").trim().notEmpty().withMessage("Password cannot be empty"),
  ],
  async (req, res) => {
    const username = req.params.username;

    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.render("addpass", {
        username,
        errors: errors.array(),
      });
    }

    const { key, value } = req.body;

    try {
      const user = await User.findOne({ username });

      user.set(key + "thisistext", value);

      await user.save();

      await user.save();

      const userObj = user.toObject();

      const excludedFields = ["_id", "username", "password", "__v"];

      const keys = Object.keys(userObj).filter(
        (k) => !excludedFields.includes(k)
      );

      res.render("digilocker", {
        keys,
        username,
      });
    } catch (err) {
      console.log(err);
      res.send("Cant add pass");
    }
  }
);

app.get("/getdoc/:username/:key", async (req, res) => {
  if (!req.session.isLoggedIn) {
    return res.redirect("/");
  }

  const { username, key } = req.params;

  if (key.includes("thisistext")) {
    try {
      const user = await User.findOne({ username });

      const value = user[key];

      res.render("passlook", {
        username,
        key,
        value,
      });
    } catch (err) {
      console.log(err);
      res.send("Something went wrong");
    }
  } else {
    const user = await User.findOne({ username });

    const value = user[key];

    res.render("getdoc", { username, key, value });
  }
});

app.get("/adddoc/:username", (req, res) => {
  if (!req.session.isLoggedIn) {
    return res.redirect("/");
  }

  const username = req.params.username;

  res.render("adddoc", { username });
});

app.post(
  "/adddoc/:username",
  upload.single("photo"),
  async (req, res) => {
    const { username } = req.params;
    const { docName } = req.body;

    try {
      const user = await User.findOne({ username });

      user.set(docName, req.file.filename);

      await user.save();

      res.redirect("/digilocker");
    } catch (err) {
      res.send("somerror");
    }
  }
);

const PORT = 3000;

mongoose
  .connect(DB_URL)
  .then(() => {
    console.log("Connected to Mongo");

    app.listen(PORT, () => {
      console.log(`Server running on address http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.log("Error while connecting to Mongo: ", err);
  });