const Course = require("../models/Course-Model.js");

module.exports.addCourse = (req, res) => {
    let{name, description, price, imgLink} = req.body;
    let newCourse = new Course({
        imgLink: imgLink,
        name: name,
        description: description,
        price: price
    })

    return newCourse.save().then(result => {
        return res.send({
            code: "COURSE-ADDED",
            message: "The course is now posted in the applicaiton.",
            result: result
        })   
    })
    .catch(error => {
        res.send({
            code: "SERVER-ERROR",
            message: "We've encountered an error while adding the course. Please try again!",
            result: error
        })
    })
}

// Get all courses
module.exports.getAllCourses = (req, res) => {
    return Course.find({}).then(result => {
        if(result == null || result.length === 0){
            return res.send({
                code: "COURSE-EMPTY",
                message: "There is no added course yet."
            })
        }else{
            return res.send({
                code: "ALL-COURSES-RESULT",
                message: "Here are the list of courses.",
                result: result
            })
        }
    })
}

// Get all active courses
module.exports.getAllActiveCourses = (req, res) => {
    return Course.find({isActive: true}).then(result => {
        if(result == null || result.length === 0){
            return res.send({
                code: "COURSE-EMPTY",
                message: "There is no added course yet."
            })
        }else{
            return res.send({
                code: "ALL-ACTIVE-COURSES-RESULT",
                message: "Here are the list of active courses.",
                result: result
            })
        }
    })
}

// Get all inactive courses
module.exports.getAllInactiveCourses = (req, res) => {
    return Course.find({isActive: false}).then(result => {
        if(result == null || result.length === 0){
            return res.send({
                code: "COURSE-EMPTY",
                message: "There is no added course yet."
            })
        }else{
            return res.send({
                code: "ALL-INACTIVE-COURSES-RESULT",
                message: "Here are the list of inactive courses.",
                result: result
            })
        }
    })
}

// Get specific course
module.exports.getSpecificCourse = (req, res) => {
    const {courseId} = req.params;
    return Course.findById(courseId).then(result => {
        if(result == null || result.length === 0){
            return res.send({
                code: "COURSE-NOT-FOUND",
                message: "The course cannot be found."
            })
        }else{
            return res.send({
                code: "COURSE-FOUND",
                message: `The data from ${courseId.toUpperCase()}`,
                result: result
            })
        }
    })
}

// Archive course
module.exports.archiveCourse = (req,res) => {
    const {courseId} = req.params;
    const updateField = {
        isActive: false
    }

    return Course.findByIdAndUpdate(courseId, updateField).then(result => {
        if(result === null || result.length === 0){
            res.send({
                code: "COURSE-NOT-FOUND",
                message: "Cannot found course with the provided ID."
            })
        }else{
            res.send({
                code: "COURSE-ARCHIVED-SUCCESSFULLY",
                message: "The couse is now in archives.",
                result: result
            })
        }
    })
}

// Unarchive course
module.exports.activateCourse = (req,res) => {
    const {courseId} = req.params;
    const updateField = {
        isActive: true
    }

    return Course.findByIdAndUpdate(courseId, updateField).then(result => {
        if(result === null || result.length === 0){
            res.send({
                code: "COURSE-NOT-FOUND",
                message: "Cannot found course with the provided ID."
            })
        }else{
            res.send({
                code: "COURSE-ACTIVATED-SUCCESSFULLY",
                message: `${result.name} is now activated.`,
                result: result
            })
        }
    })
}