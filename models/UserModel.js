const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  identifier: {
    type: String,
    index: true,
    unique: true,
    sparse: true,
    validate: {
      validator: function (value) {
        // Validate if the value is either a valid email or phone number
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        const phoneRegex = /^(\+88)?01[3-9]\d{8}$/;
        return emailRegex.test(value) || phoneRegex.test(value);
      },
      message: "Please provide a valid email or phone number!",
    },
  },
  password: { type: String },
});

userSchema.pre("save", async function hashPassword(next) {
  if (!this.isModified("password")) return next();

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);

  next();
});

userSchema.pre("findOneAndUpdate", async function hashPassword(next) {
  const update = this.getUpdate();

  if (update.password) {
    const salt = await bcrypt.genSalt(10);
    update.password = await bcrypt.hash(update.password, salt);
  }

  next();
});

const User = mongoose.model("User", userSchema);
module.exports = User;
