import React, { useState, useEffect } from 'react'
import { Form, Input, message, Modal, Select, Table, DatePicker } from "antd";
import {
  UnorderedListOutlined,
  AreaChartOutlined,
  EditOutlined,
  DeleteOutlined,
} from "@ant-design/icons";
import Layout from './../components/Layout/Layout'
import axios from 'axios';
import moment from 'moment';
import Spinner from "./../components/Spinner";
import Analytics from '../components/Analytics';
const { RangePicker } = DatePicker;

const HomePage = () => {
  const [showModal, setShowModal] = useState(false)
  const [loading, setLoading] = useState(false)
  const [allTransaction, setAllTransaction] = useState([])
  const [frequency, setFrequency] = useState('7')
  const [selectedDate, setSelectedDate] = useState([]);
  const [type, setType] = useState("all");
  const [viewData, setViewData] = useState("table");
  const [editable, setEditable] = useState(null);

  //table data
  const columns = [
    {
      title: 'Date',
      dataIndex: 'date',
      render: (text) => <span>{moment(text).format("YYYY-MM-DD")}</span>,       //target the text we are recieving
    },
    {
      title: "Amount",
      dataIndex: "amount",
    },
    {
      title: "Type",
      dataIndex: "type",
    },
    {
      title: "Category",
      dataIndex: "category",
    },
    {
      title: "Reference",
      dataIndex: "reference",
    },
    {
      title: "Actions",
      render : (text,record) => (
        <div>
          <EditOutlined 
           onClick={() => {
            setEditable(record)
            setShowModal(true)
          }}/>
          <DeleteOutlined 
            className='mx-2'
            onClick={() => {
              handleDelete(record);
            }}/>
        </div>
      )
    },
  ]

  //to fetch all transactions
  const getAllTransactions = async () => {
    try {
      const user = JSON.parse(localStorage.getItem("user"));
      setLoading(true);                                                         //Show spinner
      const res = await axios.post("/transactions/get-transaction", {
        userid: user._id,
        frequency,
        selectedDate,
        type,
      });
      setLoading(false);                                                         //Set loading to false when we get a response
      setAllTransaction(res.data);                                               //Update transactions data
      console.log(res.data);
    } catch (error) {
      console.log(error);
      message.error("Fetch issue with transaction");
    }
  };

  // useEffect hook to fetch transactions initially
  useEffect(() => {
    getAllTransactions();
  }, [frequency, selectedDate, type]);                                          //Call the effect whenever these values change

  //delete handler
  const handleDelete = async (record) => {
    try {
      setLoading(true);
      await axios.post("transactions/delete-transaction", {
        transactionId: record._id,
      });
      setLoading(false);
      message.success("Transaction Deleted!");
      getAllTransactions();                                                     //After successful deletion, fetch all transactions again
    } catch (error) {
      setLoading(false);
      console.log(error);
      message.error("Unable to delete");
    }
  };

  //form handling
  const handleSubmit = async (values) => {
    try{
      const user = JSON.parse(localStorage.getItem("user"));
      setLoading(true);
      if (editable) {
        await axios.post("/transactions/edit-transaction", {
          payload: {
            ...values,
            userId: user._id,
          },
          transacationId: editable._id,
        });
        setLoading(false);
        message.success("Transaction Updated Successfully");
        getAllTransactions();
      } else {
        await axios.post("/transactions/add-transaction", {
          ...values,                                               //spread values means pass all data of form
          userid: user._id,                                        //user that we get from local storage having _id field
        });
        setLoading(false);
        message.success("Transaction Added Successfully");          //message we get form antdesign
        getAllTransactions();
      }
      setShowModal(false)
      setEditable(null)
    }
    catch (error) {
      setLoading(false);
      message.error("Please fill all fields");
    }
  }

  return (
    <Layout>
      {loading && <Spinner />} 
      <div className='filters'>
        <div>
          <h1>Select Frequency</h1>
          <Select value={frequency} onChange={(values) => setFrequency(values)}>
             <Select.Option value="7">LAST 1 Week</Select.Option>
             <Select.Option value="30">LAST 1 Month</Select.Option>
             <Select.Option value="365">LAST 1 Year</Select.Option>
             <Select.Option value="custom">custom</Select.Option>
          </Select>
          {frequency === "custom" && (                  //we have to show range picker when frequency=custom
            <RangePicker
              value={selectedDate}
              onChange={(values) => setSelectedDate(values)}
            />
          )}
        </div>

        <div className="filter-tab ">
           <h6>Select Type</h6>
           <Select value={type} onChange={(values) => setType(values)}>
             <Select.Option value="all">ALL</Select.Option>
             <Select.Option value="income">INCOME</Select.Option>
             <Select.Option value="expense">EXPENSE</Select.Option>
           </Select>
        </div>

        <div className="switch-icons">
          <UnorderedListOutlined
            className={`mx-2 ${                                 //use classes based on condition
              viewData === "table" ? "active-icon" : "inactive-icon"
            }`}
            onClick={() => setViewData("table")}
          />
          <AreaChartOutlined
            className={`mx-2 ${                                 //use classes based on condition
              viewData === "analytics" ? "active-icon" : "inactive-icon"
            }`}
            onClick={() => setViewData("analytics")}
          />
        </div>

        <div>
          <button 
            className='btn btn-primary'
            onClick={() => setShowModal(true)}
          >
            Add New
          </button>
        </div>
      </div>

      <div className='content'>
        {viewData === "table" ? (                                     //if table then show table else show analytics
          <Table columns={columns} dataSource={allTransaction} />
        ) : (
          <Analytics allTransaction={allTransaction} />
        )}
      </div>

      <Modal title={editable ? "Edit Transaction" : "Add Transaction"}
       open={showModal}
       onCancel={() => setShowModal(false)}
       footer={false}
      >
        <Form layout="vertical" onFinish={handleSubmit} initialValues={editable}>
          <Form.Item label="Amount" name="amount">
            <Input type="text" required/>
          </Form.Item>

          <Form.Item label="Type" name="type">
            <Select>
                <Select.Option value="income">Income</Select.Option>
                <Select.Option value="expense">Expense</Select.Option>
            </Select>
          </Form.Item>

          <Form.Item label="Category" name="category">
             <Select>
               <Select.Option value="salary">Salary</Select.Option>
               <Select.Option value="tip">Tip</Select.Option>
               <Select.Option value="project">Project</Select.Option>
               <Select.Option value="food">Food</Select.Option>
               <Select.Option value="movie">Movie</Select.Option>
               <Select.Option value="bills">Bills</Select.Option>
               <Select.Option value="medical">Medical</Select.Option>
               <Select.Option value="fee">Fee</Select.Option>
               <Select.Option value="tax">Tax</Select.Option>
             </Select>
          </Form.Item>

          <Form.Item label="Date" name="date">
             <Input type="date" />
          </Form.Item>

          <Form.Item label="Reference" name="reference">
             <Input type="text" required />
          </Form.Item>

          <Form.Item label="Description" name="description">
             <Input type="text" required />
          </Form.Item>

          <div className="d-flex justify-content-end">
             <button type="submit" className="btn btn-primary">
              {" "}
               SAVE
             </button>
          </div>
        </Form>
      </Modal>
    </Layout>
  )
}
export default HomePage

//content inside layout works as a child



