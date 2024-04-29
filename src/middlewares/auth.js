const { verifyAccessToken, verifyTempToken } = require("../tokens");
const { isPasswordCorrect } = require("../user");

const authMiddleware = (auth) => {
  return async (req, res, next) => {
    const authHeader = req.headers.authorization;
    const accessToken = authHeader && authHeader.split(" ")[1];
    if (!accessToken) {
      res.status(401).json({
        code: "auth/missing-access-token",
        message: "Missing access token.",
      });
      return;
    }

    try {
      const user = await verifyAccessToken(auth, accessToken);
      req.user = user;
      next();
    } catch (error) {
      res.status(error.status).json(error);
    }
  };
};

const passwordMiddleware = (auth) => {
  return async (req, res, next) => {
    const { password } = req.body;

    if (!password) {
      res.status(400).json({
        code: "auth/missing-credentials",
        message: "Password is required",
      });
      return;
    }

    try {
      const passwordMatch = await isPasswordCorrect(
        auth,
        req.user._id,
        password
      );

      if (passwordMatch) {
        next();
      } else {
        res
          .status(401)
          .json({ code: "auth/invalid-password", message: "Invalid password" });
      }
    } catch (error) {
      res.status(error.status).json(error);
    }
  };
};

const tempAuthMiddleware = function (auth) {
  return async function (req, res, next) {
    const authHeader = req.headers.authorization;
    const tempToken = authHeader.split(" ")[1];

    if (!tempToken) {
      res.status(401).json({ message: "Missing temporary token" });
      return;
    }

    try {
      const user = await verifyTempToken(auth, tempToken);
      req.user = user;
      next();
    } catch (err) {
      res.status(err.status).json(err);
    }
  };
};

module.exports = {
  authMiddleware,
  passwordMiddleware,
  tempAuthMiddleware,
};
