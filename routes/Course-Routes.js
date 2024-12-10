const express = require("express");
// Express routing component
const router = express.Router();
const courseController = require("../controllers/Course-Controllers.js");

// Create Course
router.post("/", courseController.addCourse);

// Get all courses
router.get("/all", courseController.getAllCourses);

// Get all active courses
router.get("/all/active", courseController.getAllActiveCourses);

// Get all inactive courses
router.get("/all/inactive", courseController.getAllInactiveCourses);

// Get specific course
router.get("/search/:courseId", courseController.getSpecificCourse);

// Archive course
router.put("/archive/:courseId", courseController.archiveCourse);

// Archive course
router.put("/activate/:courseId", courseController.activateCourse);




module.exports = router;