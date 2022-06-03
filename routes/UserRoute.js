const {
  createUser,
  login,
  resetPassword,
} = require("../controller/UserController");

router.post(
  "/signup",
  ValidateRequest({
    body: {
      type: "object",
      properties: {
        name: {
          type: "string",
          minLength: 1,
          maxLength: 255,
        },
        mobile: {
          type: "string",
          format: "phoneNumber",
        },
        email: {
          type: "string",
          format: "email",
        },
        password: {
          type: "string",
        },
      },
    },
  }),
  async (req, res) => {
    try {
      let user = await createUser(req.body);
      res.status(user.status).json(user);
    } catch (error) {
      res.status(500).json(error);
    }
  }
);

router.post(
  "/login",
  ValidateRequest({
    body: {
      type: "object",
      properties: {
        email: {
          type: "string",
          format: "email",
        },
        password: {
          type: "string",
        },
      },
    },
  }),
  async (req, res) => {
    try {
      let user = await login(req.body);
      res.status(user.status).json(user);
    } catch (error) {
      res.status(500).json(error);
    }
  }
);

router.post(
  "/resetPassword",
  ValidateRequest({
    body: {
      type: "object",
      properties: {
        password: {
          type: "string",
        },
        newPassword: {
          type: "string",
        },
      },
    },
  }),
  async (req, res) => {
    try {
      let user = await resetPassword(req.body);
      res.status(user.status).json(user);
    } catch (error) {
      res.status(500).json(error);
    }
  }
);

module.exports = router;
