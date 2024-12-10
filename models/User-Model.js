const mongoose = require("mongoose");

// Schema/Blueprint of DATA
const userSchema = new mongoose.Schema({
    firstName: String,
    middleName: String,
    lastName: String,
    email: String,
    contactNumber: String,
    password: String,
    isAdmin: {
        type: Boolean,
        default: false
    }
});

module.exports = mongoose.model("User", userSchema);