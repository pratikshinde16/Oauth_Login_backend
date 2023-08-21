const { Db } = require("mongodb");
const mongoose = require("mongoose");

mongoose.set('strictQuery',true)

module.exports = () => {
  try {

    const uri = process.env.ATLAS_URI;
    mongoose.connect(uri,{});
    console.log("Connected to Database Successfully");
  } catch (error) {
    console.log(error);
    console.log("Connection Failed");
  }
};