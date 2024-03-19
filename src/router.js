const express = require("express");
const router = express.Router();
const {
  createUser,
  verifyAccessToken,
  getNewTokens,
  login,
  logout,
} = require("./main");

const authRouter = (auth) => {
  router.post("/register", async (req, res) => {
    const { email, password } = req.body;

    try {
      const user = await createUser(auth, { email, password });
      res.status(201).json(user);
    } catch (error) {
      res.status(error.status).json(error);
    }
  });

  router.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {
      const user = await login(auth, { email, password });
      res.status(200).json(user);
    } catch (error) {
      res.status(error.status).json(error);
    }
  });

  router.post("/logout", async (req, res) => {
    const { refreshToken } = req.body;

    try {
      await logout(auth, refreshToken);
      res.status(204).end();
    } catch (error) {
      res.status(error.status).json(error);
    }
  });

  router.post("/refresh", async (req, res) => {
    const { refreshToken } = req.body;

    try {
      const tokens = await getNewTokens(auth, refreshToken);
      res.status(200).json(tokens);
    } catch (error) {
      res.status(error.status).json(error);
    }
  });

  return router;
};

module.exports = authRouter;
