# InfinityUser server

Have you ever wanted to have a user system in your project but didn't want to spend time creating it? InfinityUser Admin is the solution for you. It is a user system that is easy to use and easy to implement. It is also very customizable and has a lot of features.

## Features

- registration
- login
- logout
- persistent sessions using JWT

## Installation

First you have to install [Node.js](https://nodejs.org/en/). Then you can install InfinityUser Admin using npm:

```bash
npm install @infinity-frame/infinityuser-server
```

Next, you will need to have [Mongoose](https://mongoosejs.com/) installed. You can install it using npm:

```bash
npm install mongoose
```

You will alse need to set up the Mongoose connection. You can find more information on how to do that [here](https://mongoosejs.com/docs/index.html).

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

First you will need to install [Express](https://expressjs.com/). You can install it using npm:

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

Now you can use the following routes:

- `POST /auth/register`
  - Body: `{ email: "yourEmail", password: "yourPassword" }`
- `POST /auth/login`
  - Body: `{ email: "yourEmail", password: "yourPassword" }`
- `POST /auth/refresh`
  - Body: `{ refreshToken: "yourRefreshToken" }`
- `POST /auth/logout`
  - Body: `{ refreshToken: "yourRefreshToken" }`
- `DELETE /auth/delete`
- `PUT /auth/email`
  - Body: `{ email: "yourNewEmail" }`
- `PUT /auth/password`
  - Body: `{ password: "yourCurrentPassword", newPassword: "yourNewPassword" }`

### Individual functions

You can also use the individual functions in your own code. Here are the available functions:

- `createUser(auth,email, password, data)` - `data` is optional
- `login(auth, { email, password })`
- `verifyAccessToken(auth, accessToken)`
- `getNewTokens(auth, refreshToken)`
- `logout(auth, refreshToken)`
- `deleteUser(auth, userId)`
- `isPasswordCorrect(auth, userId, password)`
- `getUser(auth, userId)`
- `updateEmail(auth, userId, newEmail)`
- `changePassword(auth, userId, newPassword)`
- `updateUserData(auth, userId, data)`
- `suspendUser(auth, userId)`
- `unsuspendUser(auth, userId)`
