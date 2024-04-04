const express = require("express");
const router = express.Router();
const {
  createUser,
  login,
  logout,
  deleteUser,
  updateEmail,
  changePassword,
  getUser,
  updateUserData,
} = require("./user");
const { getNewTokens } = require("./tokens");
const { authMiddleware, passwordMiddleware } = require("./middlewares/auth");
const { generateTOTP, validateTOTP, removeTOTP } = require("./otp.js");
const { getTwoFa } = require("./twofactor.js");

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
    router.get("/two-fa/:userId", async function (req, res) {
      try {
        const twofa = await getTwoFa(auth, req.params.userId);
        res.send(twofa);
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
    });
    router.post("/two-fa/generate-totp/:userId", async function (req, res) {
      try {
        const totp = await generateTOTP(
          auth,
          req.params.userId,
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
    });
    router.get("/two-fa/validate-totp/:userId", async function (req, res) {
      if (!req.headers.code) {
        res.status(400).json({
          code: "auth/missing-totp-code",
          message: "Missing the TOTP code to validate.",
        });
        return;
      }
      try {
        const totp = await validateTOTP(
          auth,
          req.headers.code,
          req.params.userId
        );
        if (totp) {
          res.json({
            code: "validation-success",
            message: "TOTP code is valid.",
          });
        } else {
          res.status(403).json({
            code: "invalid-totp",
            message: "The provided TOTP code is invalid for this user.",
          });
        }
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
    });
    router.delete("/two-fa/remove-totp/:userId", async function (req, res) {
      try {
        const twofa = await removeTOTP(
          auth,
          req.params.userId,
          req.body.identifier
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
    });
  }

  return router;
};

module.exports = authRouter;
