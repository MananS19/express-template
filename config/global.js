global.express = require("express");
global.app = express();
require("dotenv").config();
global.router = express.Router();
global.mongoose = require("mongoose");
global.crypto = require("crypto");
global.ObjectId = mongoose.Types.ObjectId;
global.moment = require("moment");
global._ = require("lodash");

const Ajv = require("ajv");
global.ajv = new Ajv();
//Validators
ajv.addFormat("objectId", {
  type: "string",
  validate: (data) => {
    return ObjectId.isValid(data);
  },
});
ajv.addFormat("phoneNumber", {
  type: "string",
  validate: (data) => {
    const reg = /^(\+91[\-\s]?)?[0]?(91)?[789]\d{9}$/;
    return reg.test(data);
  },
});
ajv.addFormat("email", {
  type: "string",
  validate: (data) => {
    const reg =
      /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/;
    return reg.test(data);
  },
});

global.ValidateRequest = (validationObj) => {
  return (req, res, next) => {
    const errorData = {};
    _.each(validationObj, (schema, key) => {
      const validate = ajv.compile(schema);
      const dataToValidate = req[key];
      var valid = validate(dataToValidate);
      if (!valid) {
        errorData[key] = validate.errors;
      }
    });
    if (!_.isEmpty(errorData)) {
      let instancePath = errorData.body[0].instancePath
        ? errorData.body[0].instancePath.split("/") + " "
        : "";
      let errorMessage = instancePath + errorData.body[0].message;
      res.status(400).json({
        status: 400,
        message: errorMessage,
        data: {},
      });
    } else {
      next();
    }
  };
};
