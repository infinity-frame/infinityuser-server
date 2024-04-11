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
const {
  getNewTokens,
  generateAccessToken,
  generateRefreshToken,
} = require("./tokens");
const {
  authMiddleware,
  passwordMiddleware,
  tempAuthMiddleware,
} = require("./middlewares/auth");
const { generateTOTP, removeTOTP } = require("./twofa/totp.js");
const { verifyTwoFa } = require("./twofa/twofactor.js");

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

  if (auth.settings.twofa) {
    router.post(
      "/two-fa/verify/:method",
      tempAuthMiddleware(auth),
      async function (req, res) {
        try {
          await verifyTwoFa(
            auth,
            req.params.method,
            req.user._id,
            req.body.code
          );
          const refreshToken = await generateRefreshToken(auth, req.user._id);
          const accessToken = await generateAccessToken(auth, req.user._id);
          res.json({ _id: req.user._id, refreshToken, accessToken });
        } catch (err) {
          if (typeof err.status == "undefined" || err.status == 500) {
            res.status(500).json({
              code: "internal-server-error",
              message:
                "An internal server error occured, please contact the administrators.",
            });
            console.error(err);
          } else {
            res.status(err.status).json(err);
          }
        }
      }
    );
    router.post(
      "/two-fa/totp",
      authMiddleware(auth),
      async function (req, res) {
        try {
          const totp = await generateTOTP(
            auth,
            req.user._id,
            req.body.identifier
          );
          res.json({
            code: "generation-success",
            message: "TOTP generated successfully.",
            url: totp.url,
          });
        } catch (err) {
          if (typeof err.status == "undefined" || err.status == 500) {
            res.status(500).json({
              code: "internal-server-error",
              message:
                "An internal server error occured, please contact the administrators.",
            });
            console.error(err);
          } else {
            res.status(err.status).json(err);
          }
        }
      }
    );
    router.delete(
      "/two-fa/totp/:identifier",
      authMiddleware(auth),
      async function (req, res) {
        try {
          const twofa = await removeTOTP(
            auth,
            req.user._id,
            req.params.identifier
          );
          res.json({
            code: "totp-removed",
            message: "TOTP has been removed successfully.",
          });
        } catch (err) {
          if (typeof err.status == "undefined" || err.status == 500) {
            res.status(500).json({
              code: "internal-server-error",
              message:
                "An internal server error occured, please contact the administrators.",
            });
            console.error(err);
          } else {
            res.status(err.status).json(err);
          }
        }
      }
    );
  }

  return router;
};

module.exports = authRouter;
