require("./global");

const authenticateUser = async (req, res, next) => {
  var nonSecurePaths = ["/", "/user/signup", "/user/login"];
  if (_.includes(nonSecurePaths, req.path)) {
    next();
  } else {
    if (!_.isEmpty(req.header("accessToken"))) {
      try {
        const accesstoken = req.header("accessToken");
        // verifying the access token
        let isVerifiedToken = await verifyToken(accesstoken);
        req.isAuthenticated = true;
        req.user = isVerifiedToken;
        next();
      } catch (e) {
        req.isAuthenticated = false;
        res.status(401).send(e);
      }
    } else {
      req.isAuthenticated = false;
      res.status(401).send("Not Authorized");
    }
  }
  async function verifyToken(token) {
    return new Promise((resolve, reject) => {
      jwt.verify(token, jwtKey, async function (err, decoded) {
        if (err) {
          reject(err);
        } else {
          resolve(decoded);
        }
      });
    });
  }
};
async function signJwtToken(data) {
  const accessToken = await jwt.sign(data, jwtKey, {
    expiresIn: "24h",
  });
  return accessToken;
}
module.exports = { authenticateUser, signJwtToken };

app.use(cors());
app.use(authenticateUser);
