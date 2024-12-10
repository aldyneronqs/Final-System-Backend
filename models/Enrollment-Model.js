const mongoose = require("mongoose");

// Schema/Blueprint of DATA
const enrollmentSchema = new mongoose.Schema({
    userId: String,
    enrolledCourse: [
        {
            courseId: String
        }
    ],
    totalPrice: Number,
    enrolledOn: {
        type: Date,
        default: Date.now
    },
    status: {
        type: String,
        default: "enrolled"
    }
});

module.exports = mongoose.model("Enrollment", enrollmentSchema);