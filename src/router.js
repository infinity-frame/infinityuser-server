const express = require("express");
const router = express.Router();
const {
  createUser,
  login,
  logout,
  deleteUser,
  updateEmail,
  changePassword,
} = require("./user");
const { getNewTokens } = require("./tokens");
const { authMiddleware, passwordMiddleware } = require("./middlewares/auth");

const authRouter = (auth) => {
  router.post("/register", async (req, res) => {
    const { email, password } = req.body;

    try {
      const user = await createUser(auth, email, password);
      res.status(201).json(user);
    } catch (error) {
      res.status(error.status).json(error);
    }
  });

  router.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {
      const user = await login(auth, email, password);
      res.status(200).json(user);
    } catch (error) {
      res.status(error.status).json(error);
    }
  });

  router.post("/logout", async (req, res) => {
    const { refreshToken } = req.body;

    try {
      await logout(auth, refreshToken);
      res.status(200).json({ message: "User logged out" });
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

  router.delete(
    "/delete",
    authMiddleware(auth),
    passwordMiddleware(auth),
    async (req, res) => {
      try {
        await deleteUser(auth, req.user._id);
        res.status(200).json({ message: "User deleted" });
      } catch (error) {
        res.status(error.status).json(error);
      }
    }
  );

  router.put(
    "/email",
    authMiddleware(auth),
    passwordMiddleware(auth),
    async (req, res) => {
      const { email } = req.body;

      try {
        const user = await updateEmail(auth, req.user._id, email);
        res.status(200).json(user);
      } catch (error) {
        res.status(error.status).json(error);
      }
    }
  );

  router.put(
    "/password",
    authMiddleware(auth),
    passwordMiddleware(auth),
    async (req, res) => {
      const { newPassword } = req.body;

      try {
        const user = await changePassword(auth, req.user._id, newPassword);
        res.status(200).json(user);
      } catch (error) {
        res.status(error.status).json(error);
      }
    }
  );

  if (auth.settings.twofa != null) {
    router.post("/:userId/two-fa/generate-totp", function (req, res) {});
  }

  return router;
};

module.exports = authRouter;
