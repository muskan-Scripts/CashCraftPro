import React, { useState, useEffect } from "react";
import { Form, Input, message } from "antd";
import { Link, useNavigate } from "react-router-dom";
import axios from "axios";
import Spinner from "../components/Spinner";
import "../styles/RegisterPage.css";

const Register = () => {
  const navigate = useNavigate();                                        //to navigate/redirect from one page to another
  const [loading, setLoading] = useState(false);

  //form submit
  const submitHandler = async (values) => {
    try {
      setLoading(true);
      await axios.post("users/register", values);
      // await axios.post("http://localhost:8080/api/v1/users/register", values);

      message.success("Registeration Successfull");
      setLoading(false);
      navigate("/login");                                                 //redirect to login page
    } catch (error) {
      setLoading(false);
      message.error("Something went wrong");
    }
  };

  //prevent for login user
  useEffect(() => {
    if (localStorage.getItem("user")) {           //if we get user then navigate it to homepage
      navigate("/");
    }
  }, [navigate]);

  // useEffect(() => {
  //   axios.get('http://localhost:8080/test').then(response => {
  //     console.log(response.data); 
  //   })
  // }, [])

  return (
    <>
      <div className="register-page ">
        {loading && <Spinner />}
        <Form
          className="register-form" 
          layout="vertical" 
          onFinish={submitHandler}
        >
          <h2>Register Form</h2>
          <Form.Item label="Name" name="name">
            <Input />
          </Form.Item>
          <Form.Item label="Email" name="email">
            <Input type="email" />
          </Form.Item>
          <Form.Item label="Password" name="password">
            <Input type="password" />
          </Form.Item>
          <div className="d-flex justify-content-between">
            <Link to="/login">Already Register ? Cleck Here to login</Link>
            <button className="btn btn-primary">Resgiter</button>
          </div>
        </Form>
      </div>
    </>
  );
};

export default Register;


//if loading is true then show spinner
//link is added to login page,if already register then it directly goes to login page
//in ant design,there is onFinish instead of onSubmit
