const User = require("../model/User");

async function createUser(data) {
  try {
    data.password = crypto
      .createHmac("sha256", process.env.SHA_SALT)
      .update(data.password)
      .digest("hex");
    const user = new User(data);
    let saveData = await user.save();
    return {
      status: 201,
      message: "User created successfully",
      data: saveData,
    };
  } catch (error) {
    throw new Error(error);
  }
}

async function login(data) {
  try {
    let user = await User.findOne({ email: data.email });
    if (!user) {
      return {
        status: 404,
        message: "User not found",
        data: {},
      };
    }
    let password = crypto
      .createHmac("sha256", process.env.SHA_SALT)
      .update(data.password)
      .digest("hex");
    if (password !== user.password) {
      return {
        status: 401,
        message: "Invalid password",
        data: {},
      };
    }
    return {
      status: 200,
      message: "Login successful",
      data: user,
    };
  } catch (error) {
    throw new Error(error);
  }
}

async function resetPassword(data) {
  try {
    let user = await User.findOne({ _id: data.id });
    if (!user) {
      return {
        status: 404,
        message: "User not found",
        data: {},
      };
    }
    let password = crypto
      .createHmac("sha256", process.env.SHA_SALT)
      .update(data.password)
      .digest("hex");
    if (password !== user.password) {
      return {
        status: 401,
        message: "Invalid password",
        data: {},
      };
    }
    user.password = crypto
      .createHmac("sha256", process.env.SHA_SALT)
      .update(data.newPassword)
      .digest("hex");
    let saveData = await user.save();
    return {
      status: 200,
      message: "Password reset successful",
      data: saveData,
    };
  } catch (error) {
    throw new Error(error);
  }
}

module.exports = { createUser, login, resetPassword };
