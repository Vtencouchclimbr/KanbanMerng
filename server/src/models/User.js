import mongoose from "mongoose";
import bcrypt from "bcrypt";

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true
    },
    email: {
      type: String,
      required: true,
      unique: true,
      match: [/.+@.+\..+/, "Must use a valid email address"]
    },
    password: {
      type: String,
      required: true
    }
  },
  // set this to use virtual below
  {
    toJSON: {
      virtuals: true
    }
  }
);

// hash user password
userSchema.pre("save", async function(next) {
  if (this.isNew || this.isModified("password")) {
    const saltRounds = 10;
    this.password = await bcrypt.hash(this.password, saltRounds);
  }

  next();
});

// create a virtual called `id` that's value is the string version of the user's _id field
userSchema.virtual("id").get(function() {
  return this._id.toHexString();
});

// custom method to compare and validate password for logging in
userSchema.methods.isCorrectPassword = async function(password) {
  return await bcrypt.compare(password, this.password);
};

const User = mongoose.model("User", userSchema);

export default User;
