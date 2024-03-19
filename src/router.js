const express = require("express");
const router = express.Router();
const { createUser, login, logout, deleteUser } = require("./user");
const { verifyAccessToken, getNewTokens } = require("./tokens");

const authRouter = (auth) => {
  router.post("/register", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
      res.status(400).json({
        code: "auth/missing-credentials",
        message: "Email and password are required",
      });
      return;
    }

    try {
      const user = await createUser(auth, { email, password });
      res.status(201).json(user);
    } catch (error) {
      res.status(error.status).json(error);
    }
  });

  router.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
      res.status(400).json({
        code: "auth/missing-credentials",
        message: "Email and password are required",
      });
      return;
    }

    try {
      const user = await login(auth, { email, password });
      res.status(200).json(user);
    } catch (error) {
      res.status(error.status).json(error);
    }
  });

  router.post("/logout", async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      res.status(400).json({
        code: "auth/missing-refresh-token",
        message: "Refresh token is required",
      });
      return;
    }

    try {
      await logout(auth, refreshToken);
      res.status(200).json({ message: "User logged out" });
    } catch (error) {
      res.status(error.status).json(error);
    }
  });

  router.post("/refresh", async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      res.status(400).json({
        code: "auth/missing-refresh-token",
        message: "Refresh token is required",
      });
      return;
    }

    try {
      const tokens = await getNewTokens(auth, refreshToken);
      res.status(200).json(tokens);
    } catch (error) {
      res.status(error.status).json(error);
    }
  });

  router.delete("/delete", async (req, res) => {
    const { password, userId } = req.body;

    if (!userId || !password) {
      res.status(400).json({
        code: "auth/missing-credentials",
        message: "Password and userId are required",
      });
      return;
    }

    try {
      await deleteUser(auth, { password, userId });
      res.status(200).json({ message: "User deleted" });
    } catch (error) {
      res.status(error.status).json(error);
    }
  });

  return router;
};

module.exports = authRouter;
