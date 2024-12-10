const User = require("../models/User-Model.js");
const Enroll = require("../models/Enrollment-model.js");
const bcryptjs = require("bcryptjs");
const auth = require("../auth.js");

// Register a new user
module.exports.registerUser = (req, res) => {
    const { firstName, middleName, lastName, email, contactNumber, password } = req.body;

    let newUser = new User({
        firstName,
        middleName,
        lastName,
        email,
        contactNumber,
        password: bcryptjs.hashSync(password, 10)
    });

    newUser.save()
        .then(result => {
            res.status(201).json({
                code: "REGISTRATION-SUCCESS",
                message: "You are now registered!",
                result
            });
        })
        .catch(error => {
            console.error("Registration error:", error);
            res.status(500).json({
                code: "REGISTRATION-FAILED",
                message: "An error occurred during registration. Please try again.",
                error
            });
        });
};

// Login a user
module.exports.loginUser = (req, res) => {
    const { email, password } = req.body;

    User.findOne({ email })
        .then(result => {
            if (!result) {
                return res.status(404).json({
                    code: "USER-NOT-REGISTERED",
                    message: "Please register to login."
                });
            }

            const isPasswordCorrect = bcryptjs.compareSync(password, result.password);

            if (isPasswordCorrect) {
                return res.status(200).json({
                    code: "USER-LOGIN-SUCCESS",
                    token: auth.createAccessToken(result)
                });
            } else {
                return res.status(400).json({
                    code: "PASSWORD-INCORRECT",
                    message: "Password is incorrect. Please try again."
                });
            }
        })
        .catch(error => {
            console.error("Login error:", error);
            res.status(500).json({
                code: "LOGIN-FAILED",
                message: "An error occurred during login. Please try again later.",
                error
            });
        });
};

// Check if email exists
module.exports.checkEmail = (req, res) => {
    const { email } = req.body;

    User.find({ email })
        .then(result => {
            if (result.length > 0) {
                return res.status(200).json({
                    code: "EMAIL-EXISTS",
                    message: "The user is registered."
                });
            } else {
                return res.status(404).json({
                    code: "EMAIL-NOT-EXISTING",
                    message: "The user is not registered."
                });
            }
        })
        .catch(error => {
            console.error("Check email error:", error);
            res.status(500).json({
                code: "CHECK-EMAIL-FAILED",
                message: "An error occurred while checking the email.",
                error
            });
        });
};

// Get user profile
module.exports.getProfile = async (req, res) => {
    const { id } = req.user; // Extract user ID from JWT token

    try {
        const user = await User.findById(id).select('-password'); // Don't return password

        if (!user) {
            return res.status(404).json({
                code: "USER-NOT-FOUND",
                message: "Cannot find user with the provided ID."
            });
        }

        return res.status(200).json({
            code: "USER-FOUND",
            message: "User profile fetched successfully.",
            result: user
        });
    } catch (error) {
        console.error("Error fetching profile:", error);
        return res.status(500).json({
            code: "INTERNAL_SERVER_ERROR",
            message: "An error occurred while fetching the profile.",
            error
        });
    }
};

// Enroll a user in a course
module.exports.enroll = (req, res) => {
    const { id } = req.user;

    let newEnrollment = new Enroll({
        userId: id,
        enrolledCourse: req.body.enrolledCourse,
        totalPrice: req.body.totalPrice
    });

    newEnrollment.save()
        .then(result => {
            res.status(201).json({
                code: "ENROLLMENT-SUCCESSFUL",
                message: "Congratulations, you are now enrolled!",
                result
            });
        })
        .catch(error => {
            console.error("Enrollment error:", error);
            res.status(500).json({
                code: "ENROLLMENT-FAILED",
                message: "There was an issue during your enrollment. Please try again.",
                error
            });
        });
};

// Update password
module.exports.updatePassword = async (req, res) => {
    const { userId } = req.params;  
    const { newPassword } = req.body;  

    if (!newPassword) {
        return res.status(400).json({
            code: "PASSWORD-MISSING",
            message: "New password is required."
        });
    }

    if (newPassword.length < 6) {
        return res.status(400).json({
            code: "PASSWORD-TOO-SHORT",
            message: "Password must be at least 6 characters long."
        });
    }

    try {
        const hashedPassword = await bcryptjs.hash(newPassword, 10);
        const updateField = { password: hashedPassword };

        const result = await User.findByIdAndUpdate(userId, updateField, { new: true });

        if (!result) {
            return res.status(404).json({
                code: "USER-NOT-FOUND",
                message: "Cannot find user with the provided ID."
            });
        }

        return res.status(200).json({
            code: "USER-PASSWORD-SUCCESSFULLY-UPDATED",
            message: `Password successfully updated for ${result.firstName} ${result.lastName}.`,
            result
        });
    } catch (error) {
        console.error("Error updating password:", error);
        return res.status(500).json({
            code: "INTERNAL_SERVER_ERROR",
            message: "An error occurred while updating the password.",
            error
        });
    }
};

// Update profile information
module.exports.updateProfile = async (req, res) => {
    const userId = req.user.id;
    const { firstName, lastName, email, contactNumber } = req.body;

    try {
        const updateData = {};

        if (firstName) updateData.firstName = firstName;
        if (lastName) updateData.lastName = lastName;
        if (email) updateData.email = email;
        if (contactNumber) updateData.contactNumber = contactNumber;

        const updatedUser = await User.findByIdAndUpdate(userId, updateData, { new: true }).select('-password');

        if (!updatedUser) {
            return res.status(404).json({
                code: "USER-NOT-FOUND",
                message: "Cannot find user with the provided ID."
            });
        }

        return res.status(200).json({
            code: "USER-PROFILE-UPDATED",
            message: "User profile updated successfully.",
            result: updatedUser
        });
    } catch (error) {
        console.error("Error updating profile:", error);
        return res.status(500).json({
            code: "INTERNAL_SERVER_ERROR",
            message: "An error occurred while updating the profile.",
            error
        });
    }
};
