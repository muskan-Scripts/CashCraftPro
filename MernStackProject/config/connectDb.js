const mongoose = require("mongoose");
const colors = require("colors");
const connectDb = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);                                      //await for connection to be established
    console.log(`Server Running On ${mongoose.connection.host}`.bgCyan.white);            //bg color - cyan,text - white
  } catch (error) {
    console.log(`${error}`.bgRed);
  }
};

module.exports = connectDb;
