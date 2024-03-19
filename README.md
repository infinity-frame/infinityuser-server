# InfinityUser Admin

Have you ever wanted to have a user system in your project but didn't want to spend time creating it? InfinityUser Admin is the solution for you. It is a user system that is easy to use and easy to implement. It is also very customizable and has a lot of features.

## Features

- registration
- login
- logout
- persistent sessions using JWT

## Installation

First you have to install (Node.js)[https://nodejs.org/en/]. Then you can install InfinityUser Admin using npm:

```bash
npm install infinityuser-admin
```

Next, you will need to have (Mongoose)[https://mongoosejs.com/] installed. You can install it using npm:

```bash
npm install mongoose
```

You will alse need to set up the Mongoose connection. You can find more information on how to do that (here)[https://mongoosejs.com/docs/index.html].

## Usage

First you will need to import `initAuth` from InfinityUser Admin:

```javascript
const { initAuth } = require("infinityuser-admin");
```

Then you will need to call `initAuth` with the Mongoose connection and some options:

```javascript
const { initAuth } = require("infinityuser-admin");
const mongoose = require("mongoose");

const start = async () => {
  await mongoose.connect("yourConnectionString");
  const db = mongoose.connection;

  const auth = initAuth({
    db,
    accessTokenSecret: "yourAccessTokenSecret",
    refreshTokenSecret: "yourRefreshTokenSecret",
    enableLogs: true, // Optional
  });
};

start();
```

Now, you have two options. You can either use the `authRouter` which is an Express router that you can simply import and use in your project. Or you can import the individual functions and use them in your own code.

### authRouter

First you will need to install (Express)[https://expressjs.com/]. You can install it using npm:

```bash
npm install express
```

Then you can create an Express app and use the `authRouter`:

```javascript
const { initAuth, authRouter } = require("infinityuser-admin");
const mongoose = require("mongoose");
const express = require("express");
const app = express();

const start = async () => {
  await mongoose.connect("yourConnectionString");
  const db = mongoose.connection;

  const auth = initAuth({
    db,
    accessTokenSecret: "yourAccessTokenSecret",
    refreshTokenSecret: "yourRefreshTokenSecret",
    enableLogs: true,
  });

  app.use(express.json()); // Use the JSON parser
  app.use("/auth", authRouter(auth)); // Use the authRouter

  await app.listen(3000);
  console.log("App listening on port 3000");
};

start();
```

### Individual functions

You can also use the individual functions in your own code. Here are the available functions:

- `createUser(auth, { username, password })`
- `login(auth, { username, password })`
- `verifyAccessToken(auth, accessToken)`
- `getNewTokens(auth, refreshToken)`
- `logout(auth, refreshToken)`
