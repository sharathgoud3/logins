=============middleware folder
file name :verifyToken.js
****************************middle ware to verify token
const jwt = require("jsonwebtoken");
require("dotenv").config();

exports.verifyAdminToken = async function (req, res, next) {
  try {
    let expired = null;
    const bearerHeader = req.headers["authorization"];
    let bearerToken = "";
    if (bearerHeader) {
      bearerToken = bearerHeader.split(" ")[1];
    }
// console.log(bearerToken)
    if (bearerToken) {
      jwt.verify(
        bearerToken,
        process.env.ADMIN_SECRET_KEY,
        function (err, decoded) {
          if (err) {
            try {
              expired = err;
              res
                .status(401)
                .json({ status: false, message: "Your session has expired. Please login.", expired });
            } catch (err) {
              res
                .status(401)
                .json({ status: false, message: "Your session has expired. Please login.", err });
            }
          }
          if (decoded) {
            req.userId = decoded.userId;
            req.loginTime = decoded.iat;
            // console.log(req.userId);
            //iat: 1666000967,
            // exp: 1666087367
            next();
          }
        }
      );
    } else {
      res
        .status(400)
        .json({ status: false, message: "Bearer token not defined" });
    }
  } catch (err) {
    console.log("eror", err);
    if (err.name === "JsonWebTokenError" || err.name === "TokenExpiredError") {
      return res.status(401).json({ status: false, message: "Session Expired Error",Error: err });
    }
    else{
        res
        .status(401)
        .json({ status: false, message: "Internal Server Error", error: err });
    }
  }
};

===========controller folder
****************registration 
file name == adminController.js
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const Admin = require("../../models/admin");
// admin/Emp registerations
exports.adminRegister = function (req, res) {
  try {
    Admin.findOne({
      $or: [{ email: req.body.email }, { phone: req.body.phone }],
    }).exec(async function (err, user) {
      if (user) {
        return res
          .status(420)
          .json({ sucess: false, message: "The user already exists!" });
      } else {
        const dept = await Departments.findOne(
          { _id: req.body.departmentId },
          { departmentName: 1 }
        );
          const admin = await Admin.findOne(
            { _id: req.userId },
            { _id: 1, fullName: 1 }
          );
          const bcryptedPassword = bcrypt.hashSync(req.body.password, 10);
          let logDate = new Date().toISOString();
          const adminEmpObj = new Admin({
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            fullName: `${req.body.firstName} ${req.body.lastName}`,
            email: req.body.email,
            phone: req.body.phone,
            password: bcryptedPassword,
            adminId: admin._id,
            createdBy: admin.fullName,
            logCreatedDate: logDate,
            logModifiedDate: logDate,
          }).save(function (error, userData) {
            if (error) {
              return res.status(420).json({
                sucess: false,
                message: "Bad request. User data could not be saved.",
                Error: error,
              });
            }
            if (userData) {
              res.status(200).json({
                sucess: true,
                message: "The user was successfully added. ",
              });
            }
          });
      }
    });
  } catch (err) {
    res
      .status(420)
      .json({ sucess: false, message: "Something went wrong!", Error: err });
  }
};

// admin/Emp Login/Sign in
exports.adminLogin = async function (req, res) {
  try {
    const user = await Admin.findOne(
      { $or: [{ email: req.body.email }, { phone: req.body.phone }] },
      {
        _id: 1,
        firstName: 1,
        fullName: 1,
        email: 1,
        phone: 1,
        departmentName: 1,
        password: 1,
        rolesPermissions: 1,
        status: 1,
      }
    );
    if (user) {
      let password = req.body.password;
      const pass = bcrypt.compareSync(password, user.password);
      if (pass && user.departmentName) {
        let token = jwt.sign(
          {
            userId: user._id,
            password: user.password,
            departmentName: user.departmentName,
          },
          process.env.ADMIN_SECRET_KEY,
          { expiresIn: process.env.ADMIN_EXPIRY_DATE }
        );
        const userData = {
          id: user._id,
          fullName: user.fullName,
          email: user.email,
          role: user.departmentName,
        };
        res.status(200).json({
          success: true,
          message: "You have successfully logged in.",
          token: token,
          user: userData,
        });
      } else {
        res.status(420).json({
          status: 420,
          message: "Please provide a valid password.",
        });
      }
    } else {
      res.status(404).json({
        success: false,
        message: "Please provide a valid email address or phone number.",
      });
    }
  } catch (err) {
    res.status(420).json({
      status: false,
      message: "Something went wrong!",
      Error: err,
    });
  }
};

======models folder
admin.js =file name
const mongoose = require("mongoose");
const admin = new mongoose.Schema(
  {
    firstName: {
      type: String,
      trim: true,
      index: true,
      required: true,
    },
    lastName: {
      type: String,
      trim: true,
      required: true,
    },
    fullName: {
      type: String,
    },
    email: {
      type: String,
      trim: true,
      index: true,
      required: true,
    },
    phone: {
      type: String,
      trim: true,
      index: true,
      required: true,
    },
    password: {
      type: String,
      trim: true,
      required: true,
    },
    adminId: {
      type: String,
    },
    createdBy: {
      type: String,
    },
    logCreatedDate: {
      type: String,
    },
    logModifiedDate: {
      type: String,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Admin", admin);

======routes folder
adminRoutes.js =file name

const express = require("express");
const adminRoutes = express.Router();

//controller
const adminEmpController = require("../../controllers/admin/admin.controller");

//middlewares
const verifyToken = require("../../middlewares/verifyToken");

adminRoutes.post(
  "/registerAdmin",
  verifyToken.verifyAdminToken,
  adminEmpController.adminEmpRegister
);
adminRoutes.post("/login", adminEmpController.adminEmpLogin);

module.exports = adminRoutes;
