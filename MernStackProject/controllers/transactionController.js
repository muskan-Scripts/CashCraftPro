const transactionModel = require('../models/transactionModel');
const moment = require("moment");

const getAllTransaction = async (req,res) => {
    try {
        const {frequency, selectedDate, type} = req.body
        const transactions = await transactionModel.find({
          ...(frequency !== "custom"
                ? {                                       //if frequency!==custom then write date like this
                    date: {  
                      $gt: moment().subtract(Number(frequency), "d").toDate(),
                    },
                }
                : {                                       //else write date like this
                    date: {
                      $gte: selectedDate[0],                 //access index
                      $lte: selectedDate[1],
                    },
                }),
            userid: req.body.userid,
            ...(type !== "all" && { type }),                //if we do not select type all then show type i.e selected
        })
        res.status(200).json(transactions);
    } catch (error){
        console.log(error);
        res.status(500).json(error);    
    }        
};

const deleteTransaction = async (req, res) => {
    try {
      await transactionModel.findOneAndDelete({ _id: req.body.transactionId });
      res.status(200).send("Transaction Deleted!");
    } catch (error) {
      console.log(error);
      res.status(500).json(error);
    }
};

const editTransaction = async (req, res) => {
    try {
      await transactionModel.findOneAndUpdate(
        { _id: req.body.transacationId },
        req.body.payload
      );
      res.status(200).send("Edit Successfully");
    } catch (error) {
      console.log(error);
      res.status(500).json(error);
    }
};

const addTransaction = async (req,res) => {
    try{
        const newTransaction = new transactionModel(req.body)           //store all data of ewq.body in newTransaction
        await newTransaction.save();                                    //call save method
        res.status(201).send("Transaction created");
    } catch(error){
        console.log(error);
        res.status(500).json(error);
    }
}

module.exports = {getAllTransaction, addTransaction, editTransaction, deleteTransaction}
