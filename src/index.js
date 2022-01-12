import express from "express";
import { v4 } from "uuid";
import * as yup from "yup";
import jwt from "jsonwebtoken";
import * as bcrypt from "bcryptjs";

const app = express();
app.use(express.json());
app.listen(3000, console.log("Running at http://localhost:3000"));

const config = {
  secret: "kenzie2022",
  expiresIn: "1h",
};

let database = [];

const userSchema = yup.object().shape({
  username: yup.string().required(),
  age: yup.number().positive().integer().required(),
  email: yup.string().email().required(),
  password: yup
    .string()
    .min(6)
    .required()
    .matches(
      /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/,
      "Must Contain 8 Characters, One Uppercase, One Lowercase, One Number and one special case Character"
    ),
});

const validate = (schema) => async (req, res, next) => {
  const resource = req.body;
  try {
    await schema.validate(resource);
    next();
  } catch (err) {
    res.status(400).json({ error: err.errors.join(", ") });
  }
};

const authUser = (req, res, next) => {
  let token = req.headers.authorization.split(" ")[1];

  jwt.verify(token, config.secret, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Invalid Token" });
    }
    let user = database.find((user) => user.username === decoded.username);

    req.user = user;
  });
  return next();
};

app.get("/users", authUser, (req, res) => {
  res.status(200).json({ database });
});

app.post("/users", validate(userSchema), async (req, res) => {
  try {
    let date = new Date();
    const uuid = v4();
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    const data = {
      uuid: uuid,
      username: req.body.username,
      age: req.body.age,
      email: req.body.email,
      password: hashedPassword,
      createdOn: date.toUTCString(),
    };

    database.push(data);

    const { password: data_password, ...dataWithPassword } = data;

    return res.status(201).json(dataWithPassword);
  } catch (err) {
    res.json({ message: "Error while creating an user" });
  }
});

app.put("/users/:uuid", authUser, async (req, res) => {
  try {
    const user = database.find((user) => user.uuid === req.params.uuid);
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }
    if (!req.body.hasOwnProperty("password")) {
      return res
        .status(401)
        .json({ message: "Users can only update password field!" });
    }
    if (req.user.username != user.username) {
      return res.status(403).json({
        message:
          "Unauthorized only the account owner can change its own password!",
      });
    }
    const index = database.findIndex((users) => users.uuid === user.uuid);

    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    user.password = hashedPassword;

    database[index] = user;

    res.status(204).json("");
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = database.find((user) => user.username === username);

  try {
    if (!user) {
      return res.status(401).json({ message: "User not found!" });
    }

    const match = await bcrypt.compare(password, user.password);

    let token = jwt.sign(
      { username: username, password: user.password },
      config.secret,
      { expiresIn: config.expiresIn }
    );
    if (match) {
      res.json({ access_token: token });
    } else {
      res.json({ message: "User or password mismatch!" });
    }
  } catch (err) {
    res.json({ error: err });
  }
});
